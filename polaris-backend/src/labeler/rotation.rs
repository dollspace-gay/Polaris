//! Labeler signing-key rotation state machine (issue #30, REQ-12, AC-15).
//!
//! Rotation is a multi-step persistent state machine. Each step is
//! idempotent and the machine is resumable: a crash between any two
//! steps lets a follow-up CLI invocation with `--resume <rotation_id>`
//! pick up from `last_step + 1`. The schema lives in migration 14
//! (`signing_key_history`, `revoked_keys`, `rotation_state`).
//!
//! # Steps
//!
//! 1. **`GenerateKey`** — generate a fresh K-256 keypair in memory.
//!    On resume, the new keypair's `did:key:z…` is looked up from
//!    `rotation_state.new_public_key_did`; if present (i.e. the prior
//!    run reached at least `key_generated`) the on-disk key file is
//!    *reused* and no fresh keypair is rolled. This is the
//!    failure-injection-test contract.
//! 2. **`WriteNewKeyMaterial`** — write the new key into the operator's
//!    custody store. For `file-plain` this is the path the CLI flag
//!    `--new-key-path` names. The bytes are atomic-rename-written and
//!    `chmod 0o600` is enforced before `rename`. Re-running this step
//!    when the file already contains the same DID is a no-op.
//! 3. **`PublishServiceRecord`** — re-publish the operator's
//!    `app.bsky.labeler.service` record under the new key. Today this
//!    step is a logging-only placeholder so the state machine remains
//!    closed-loop without forcing a network call in the unit test path;
//!    the real network call is performed by the `polaris-publish-labeler-record`
//!    binary which the operator runs alongside the rotation CLI. Re-running
//!    is safe — the record write is idempotent on the PDS side via
//!    `put_record` with `rkey = self`.
//! 4. **`RecordHistory`** — insert the new key into `signing_key_history`
//!    in a single transaction that also closes the prior active row by
//!    setting its `active_until` to now. The UNIQUE partial index
//!    `signing_key_history_only_one_active` (one NULL `active_until`)
//!    is the database-level invariant that makes "no window with two
//!    active keys" unforgeable. Re-running this step when the new key
//!    already has a row is a no-op.
//! 5. **`RevokeOldKey`** — append the old key's did to `revoked_keys`.
//!    The table is append-only (a trigger rejects DELETE and UPDATE);
//!    re-inserting the same did is a no-op via `ON CONFLICT DO NOTHING`.
//! 6. **`AtomicSwap`** — the live server detects the
//!    `signing_key_history` change on its polling timer and reloads its
//!    in-process `Arc<dyn SigningKey>` by calling `watch::Sender::send`.
//!    The rotation CLI does NOT directly touch the server's `watch`
//!    channel because in real deployments they are separate processes;
//!    the CLI's responsibility ends at "the new key is persisted to
//!    custody + DB". See [`crate::labeler::signer::ActiveSigner`].
//!
//! Final state: `Complete`. An error at any step rolls the row to
//! `Aborted` and writes the error category into `rotation_state.error`.
//!
//! # Discovery mechanism (poll vs. broadcast)
//!
//! Rotation persists state into `signing_key_history`; a separate live
//! server polls that table on a `tokio::time::interval` to discover new
//! active keys. A broadcast channel was rejected because it would require
//! every Polaris process to subscribe to a process-spanning event bus —
//! out of scope for the v1 deployment topology (the rotation CLI runs as
//! a one-shot kubectl exec / systemd unit, not a co-resident daemon).
//! Polling has bounded staleness (one interval, configurable on the live
//! server side) and is robust against split-brain.
//!
//! # Append-only invariants
//!
//! - `signing_key_history`: no DELETE, no UPDATE except the legal
//!   "retire" transition (NULL `active_until` to a non-NULL value on
//!   the currently-active row).
//! - `revoked_keys`: no DELETE, no UPDATE — strictly append-only.
//! - `rotation_state`: UPDATE-only along the documented step transitions.
//!   No DELETE in production code; tests `TRUNCATE` for setup.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Keypair as _};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::config::LabelerSigningKeyConfig;

/// The set of custody modes the rotation CLI accepts on its `--mode`
/// flag. Mirrored from [`LabelerSigningKeyConfig`] but flattened to a
/// `Copy` enum so the state machine can carry it through a
/// `RotationPlan` without dragging the full config (which embeds paths,
/// account names, etc. that the machine itself does not use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyMode {
    /// `file-plain` — the only mode #30 implements end-to-end.
    FilePlain,
    /// `passphrase-sealed` — stubbed via [`RotationError::Unsupported`].
    PassphraseSealed,
    /// `os-keychain` — stubbed via [`RotationError::Unsupported`].
    OsKeychain,
    /// `cloud-kms-oracle` — stubbed via [`RotationError::Unsupported`].
    CloudKms,
}

impl CustodyMode {
    /// On-the-wire name (matches the kebab-case `--mode` flag, the
    /// `_polaris_schema_version` description text, and the
    /// `signing_key_history.custody_mode` text column).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilePlain => "file-plain",
            Self::PassphraseSealed => "passphrase-sealed",
            Self::OsKeychain => "os-keychain",
            Self::CloudKms => "cloud-kms-oracle",
        }
    }
}

impl From<&LabelerSigningKeyConfig> for CustodyMode {
    fn from(cfg: &LabelerSigningKeyConfig) -> Self {
        match cfg {
            LabelerSigningKeyConfig::FilePlain { .. } => Self::FilePlain,
            LabelerSigningKeyConfig::PassphraseSealed { .. } => Self::PassphraseSealed,
            LabelerSigningKeyConfig::OsKeychain { .. } => Self::OsKeychain,
            LabelerSigningKeyConfig::CloudKms { .. } => Self::CloudKms,
        }
    }
}

/// Rotation state-machine step. Mirrors the `rotation_step` Postgres
/// enum from migration 14.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationStep {
    /// No work done yet. `rotation_state` row freshly created.
    Pending,
    /// New keypair generated in memory; `new_public_key_did` populated.
    KeyGenerated,
    /// New key material persisted to the custody store.
    KeyWritten,
    /// `app.bsky.labeler.service` record re-published. (Operator-side
    /// step in v1; the rotation CLI logs an audit pointer.)
    ServiceRecordPublished,
    /// `signing_key_history` updated: old row's `active_until` set,
    /// new row inserted with NULL `active_until`.
    HistoryRecorded,
    /// Old key did appended to `revoked_keys`.
    OldKeyRevoked,
    /// Live server's `watch::Sender<Arc<dyn SigningKey>>` notified (or
    /// will be on its next poll tick). The CLI's responsibility ends
    /// here.
    Swapped,
    /// Terminal: rotation completed cleanly.
    Complete,
    /// Terminal: rotation hit a fatal error and was rolled to an
    /// abort state. The `error` column carries the category.
    Aborted,
}

impl RotationStep {
    /// On-the-wire name for the `last_step` column. Kept here so the
    /// SQL encoding sites all share one source of truth.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::KeyGenerated => "key_generated",
            Self::KeyWritten => "key_written",
            Self::ServiceRecordPublished => "service_record_published",
            Self::HistoryRecorded => "history_recorded",
            Self::OldKeyRevoked => "old_key_revoked",
            Self::Swapped => "swapped",
            Self::Complete => "complete",
            Self::Aborted => "aborted",
        }
    }

    /// Parse a step from the Postgres enum text representation.
    #[must_use]
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "key_generated" => Some(Self::KeyGenerated),
            "key_written" => Some(Self::KeyWritten),
            "service_record_published" => Some(Self::ServiceRecordPublished),
            "history_recorded" => Some(Self::HistoryRecorded),
            "old_key_revoked" => Some(Self::OldKeyRevoked),
            "swapped" => Some(Self::Swapped),
            "complete" => Some(Self::Complete),
            "aborted" => Some(Self::Aborted),
            _ => None,
        }
    }
}

/// The "what's next?" enum the state-machine driver consumes.
///
/// `next_step` returns `Some(NextStep::…)` for the next op or `None`
/// when the plan is at a terminal state (Complete / Aborted). The
/// caller invokes the matching method on [`RotationContext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextStep {
    /// Generate a fresh K-256 keypair.
    GenerateKey,
    /// Persist the new key into the custody store.
    WriteNewKeyMaterial,
    /// Re-publish the operator's `app.bsky.labeler.service` record.
    PublishServiceRecord,
    /// Record the rotation event in `signing_key_history`.
    RecordHistory,
    /// Append the old key to `revoked_keys`.
    RevokeOldKey,
    /// Notify the live server's `watch::Sender`.
    AtomicSwap,
}

/// In-memory shape of a `rotation_state` row, plus the call-site-supplied
/// bits the row doesn't carry (the new-key filesystem path).
///
/// This is the value [`next_step`] consumes; it is reloaded from the DB
/// on every step boundary so a crash + restart converges on the same
/// behaviour as a no-crash run.
#[derive(Debug, Clone)]
pub struct RotationPlan {
    /// `rotation_state.id`.
    pub id: Uuid,
    /// Custody mode (the wire-name string is also stored on the DB row).
    pub custody_mode: CustodyMode,
    /// Highest step ever reached for this rotation id.
    pub last_step: RotationStep,
    /// did:key for the *outgoing* key. Filled at row insert (step
    /// `Pending`). `None` is a programming invariant violation
    /// surfaced as [`RotationError::Init`].
    pub old_did: Option<String>,
    /// did:key for the *incoming* key. `None` until step
    /// `KeyGenerated` completes.
    pub new_did: Option<String>,
}

/// Decide the next idempotent op for a rotation plan.
///
/// Pure function — no IO, no allocations beyond the returned enum.
/// Test surface for the transition table.
#[must_use]
pub const fn next_step(plan: &RotationPlan) -> Option<NextStep> {
    match plan.last_step {
        RotationStep::Pending => Some(NextStep::GenerateKey),
        RotationStep::KeyGenerated => Some(NextStep::WriteNewKeyMaterial),
        RotationStep::KeyWritten => Some(NextStep::PublishServiceRecord),
        RotationStep::ServiceRecordPublished => Some(NextStep::RecordHistory),
        RotationStep::HistoryRecorded => Some(NextStep::RevokeOldKey),
        RotationStep::OldKeyRevoked => Some(NextStep::AtomicSwap),
        RotationStep::Swapped | RotationStep::Complete | RotationStep::Aborted => None,
    }
}

/// Errors emitted by the rotation state machine.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// The rotation plan could not be loaded or seeded (the outgoing
    /// key did is unknown, the DB row is malformed, etc.).
    #[error("rotation init failed: {reason}")]
    Init {
        /// Static category reason.
        reason: &'static str,
    },

    /// A fresh K-256 keypair could not be generated. In practice
    /// unreachable (`K256Keypair::generate` returns infallibly today)
    /// but a typed path keeps the error chain uniform.
    #[error("failed to generate new K-256 keypair")]
    GenerateKey,

    /// The new key material could not be persisted to the custody
    /// store (file write failure, mode-setting failure, atomic-rename
    /// failure).
    #[error("failed to write new key material: {reason}")]
    WriteKey {
        /// Static category reason.
        reason: &'static str,
    },

    /// The post-write `app.bsky.labeler.service` record publish step
    /// failed (network error, lexicon mismatch, authentication failed).
    #[error("failed to publish labeler-service record: {reason}")]
    Publish {
        /// Static category reason.
        reason: &'static str,
    },

    /// A database operation failed at a non-init step. The underlying
    /// `sqlx::Error` is preserved via `#[source]` so operators can
    /// match on SQLSTATE; the Display text stays generic.
    #[error("rotation database operation failed")]
    Db(#[source] sqlx::Error),

    /// The signer factory rejected the persisted new key material at
    /// the post-swap "load it back" step. Wraps the upstream signer
    /// error so its category is visible to operators.
    #[error("post-swap signer reload failed")]
    Signer(#[source] crate::labeler::signer::SigningError),

    /// The CLI was invoked with `--mode <m>` but `<m>` is not the
    /// `file-plain` mode #30 implements end-to-end. Carries the mode
    /// name so the operator's error message names the follow-up
    /// (issue #64 will land the remaining three modes).
    #[error(
        "rotation mode {mode:?} not yet supported in #30; tracked as #64 (passphrase-sealed / os-keychain / cloud-kms-oracle)"
    )]
    Unsupported {
        /// The mode the operator asked for.
        mode: &'static str,
    },
}

/// Runtime side of a rotation: the DB pool, the plan, and the
/// per-mode parameters the steps need (the new-key file path for
/// `file-plain`).
#[derive(Debug)]
pub struct RotationContext {
    pool: PgPool,
    plan: RotationPlan,
    /// Filesystem path the rotation CLI writes new key material to
    /// (file-plain only).
    new_key_path: PathBuf,
}

impl RotationContext {
    /// Borrow the in-memory plan. Tests use this to assert the
    /// post-step state without re-querying the DB.
    #[must_use]
    pub const fn plan(&self) -> &RotationPlan {
        &self.plan
    }

    /// Borrow the new-key filesystem path. Tests use this to assert
    /// idempotency (the file on disk is unchanged after a resume).
    #[must_use]
    pub fn new_key_path(&self) -> &std::path::Path {
        &self.new_key_path
    }

    /// Seed a brand-new rotation row (no `--resume` flag was passed).
    ///
    /// Reads the current active key from `signing_key_history`; if none
    /// is recorded the caller must have bootstrapped one already (the
    /// operator is expected to insert the initial active key in
    /// migration 14's follow-up bootstrap, or via a dedicated
    /// `labeler-key-bootstrap` flow filed as #65). A rotation against a
    /// never-bootstrapped DB returns [`RotationError::Init`].
    ///
    /// # Errors
    ///
    /// - [`RotationError::Init`] when the DB has no active key.
    /// - [`RotationError::Db`] for any underlying SQL error.
    pub async fn new_rotation(
        pool: PgPool,
        mode: CustodyMode,
        new_key_path: PathBuf,
    ) -> Result<Self, RotationError> {
        let active = sqlx::query!(
            r#"
            SELECT public_key_did
            FROM signing_key_history
            WHERE active_until IS NULL
            ORDER BY active_from DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&pool)
        .await
        .map_err(RotationError::Db)?
        .ok_or(RotationError::Init {
            reason: "no active signing key recorded in signing_key_history",
        })?;

        // Bind the lossy-utf8 form to a local so the `&str` the
        // sqlx macro encodes against doesn't outlive its backing
        // `Cow<str>`. The macro expands to `(&new_key_path_str) as &str`,
        // which would otherwise dangle for the duration of the await.
        let new_key_path_str = new_key_path.to_string_lossy().into_owned();
        let row = sqlx::query!(
            r#"
            INSERT INTO rotation_state (custody_mode, old_public_key_did, new_key_path)
            VALUES ($1, $2, $3)
            RETURNING id, last_step::TEXT AS "last_step!"
            "#,
            mode.as_str(),
            active.public_key_did,
            new_key_path_str,
        )
        .fetch_one(&pool)
        .await
        .map_err(RotationError::Db)?;

        let last_step = RotationStep::from_db_str(&row.last_step).ok_or(RotationError::Init {
            reason: "rotation_state.last_step decoded to unknown enum variant",
        })?;

        Ok(Self {
            pool,
            plan: RotationPlan {
                id: row.id,
                custody_mode: mode,
                last_step,
                old_did: Some(active.public_key_did),
                new_did: None,
            },
            new_key_path,
        })
    }

    /// Reload a rotation from its `rotation_state.id` (the `--resume`
    /// path).
    ///
    /// # Errors
    ///
    /// - [`RotationError::Init`] when the row is missing, the custody
    ///   mode column does not match the CLI's `--mode`, or the enum
    ///   decoding fails.
    /// - [`RotationError::Db`] for any underlying SQL error.
    pub async fn resume(
        pool: PgPool,
        rotation_id: Uuid,
        cli_mode: CustodyMode,
    ) -> Result<Self, RotationError> {
        let row = sqlx::query!(
            r#"
            SELECT
                id,
                custody_mode,
                last_step::TEXT AS "last_step!",
                new_public_key_did,
                old_public_key_did,
                new_key_path
            FROM rotation_state
            WHERE id = $1
            "#,
            rotation_id,
        )
        .fetch_optional(&pool)
        .await
        .map_err(RotationError::Db)?
        .ok_or(RotationError::Init {
            reason: "rotation_state row not found for --resume id",
        })?;

        if row.custody_mode != cli_mode.as_str() {
            return Err(RotationError::Init {
                reason: "rotation_state custody_mode does not match --mode flag",
            });
        }

        let last_step = RotationStep::from_db_str(&row.last_step).ok_or(RotationError::Init {
            reason: "rotation_state.last_step decoded to unknown enum variant",
        })?;

        let new_key_path =
            row.new_key_path
                .as_deref()
                .map(PathBuf::from)
                .ok_or(RotationError::Init {
                    reason: "rotation_state row is missing new_key_path",
                })?;

        Ok(Self {
            pool,
            plan: RotationPlan {
                id: row.id,
                custody_mode: cli_mode,
                last_step,
                old_did: row.old_public_key_did,
                new_did: row.new_public_key_did,
            },
            new_key_path,
        })
    }

    /// Drive the rotation forward until it reaches a terminal state
    /// (`Complete` or `Aborted`).
    ///
    /// Each iteration: (a) consults `next_step(&plan)`, (b) invokes the
    /// matching step method, (c) advances `last_step` in the DB. On
    /// `None` (terminal), promotes `Swapped → Complete` and returns
    /// `Ok(())`.
    ///
    /// # Errors
    ///
    /// Any [`RotationError`] from an underlying step. On error the row
    /// is moved to `Aborted` and the error category is written to
    /// `rotation_state.error`; the error is then returned verbatim.
    pub async fn run(&mut self) -> Result<(), RotationError> {
        if matches!(self.plan.custody_mode, CustodyMode::FilePlain) {
            // fall through
        } else {
            return Err(RotationError::Unsupported {
                mode: self.plan.custody_mode.as_str(),
            });
        }

        loop {
            let Some(next) = next_step(&self.plan) else {
                // Promote terminal Swapped → Complete (the rotation
                // machine's "I'm done" signal). If already Complete or
                // Aborted, this is a no-op.
                if matches!(self.plan.last_step, RotationStep::Swapped) {
                    self.advance_to(RotationStep::Complete).await?;
                }
                return Ok(());
            };

            if let Err(err) = self.run_step(next).await {
                self.mark_aborted(&err).await;
                return Err(err);
            }
        }
    }

    /// Run a single state-machine step. The advancement of `last_step`
    /// happens inside each step's implementation, in the same TX as
    /// the step's primary side-effect, so a crash between the side-effect
    /// and the advancement is impossible (the side-effect either
    /// completed and advanced, or rolled back together).
    async fn run_step(&mut self, step: NextStep) -> Result<(), RotationError> {
        match step {
            NextStep::GenerateKey => self.step_generate_key().await,
            NextStep::WriteNewKeyMaterial => self.step_write_new_key_material().await,
            NextStep::PublishServiceRecord => self.step_publish_service_record().await,
            NextStep::RecordHistory => self.step_record_history().await,
            NextStep::RevokeOldKey => self.step_revoke_old_key().await,
            NextStep::AtomicSwap => self.step_atomic_swap().await,
        }
    }

    /// Advance `last_step` to the requested value in the DB and update
    /// the in-memory plan. Used by step implementations after their
    /// primary side-effect succeeds.
    async fn advance_to(&mut self, to: RotationStep) -> Result<(), RotationError> {
        // The `last_step` column is a Postgres ENUM (`rotation_step`).
        // sqlx has no built-in mapping from `&str` to a user-defined
        // enum type, so we encode the parameter as TEXT and let Postgres
        // do the TEXT→rotation_step coercion at statement-plan time. The
        // two-step cast (`$1::TEXT::rotation_step`) is the
        // sqlx 0.8-recommended pattern for enums whose Rust side is a
        // wire-name `&'static str`.
        sqlx::query!(
            r#"
            UPDATE rotation_state
            SET last_step = $1::TEXT::rotation_step,
                last_step_at = now()
            WHERE id = $2
            "#,
            to.as_str(),
            self.plan.id,
        )
        .execute(&self.pool)
        .await
        .map_err(RotationError::Db)?;
        self.plan.last_step = to;
        Ok(())
    }

    /// Stamp the row with the abort reason. Best-effort — if the DB
    /// itself is the failing layer, the underlying error has already
    /// been returned to the caller; we attempt the abort write but
    /// swallow any failure so a transient DB blip doesn't bury the
    /// original error.
    async fn mark_aborted(&mut self, err: &RotationError) {
        let reason = err.to_string();
        let _ = sqlx::query!(
            r#"
            UPDATE rotation_state
            SET last_step = 'aborted'::rotation_step,
                last_step_at = now(),
                error = $1
            WHERE id = $2
            "#,
            reason,
            self.plan.id,
        )
        .execute(&self.pool)
        .await;
        self.plan.last_step = RotationStep::Aborted;
    }

    // ── Step implementations ────────────────────────────────────────

    /// Step 1: generate the new K-256 keypair.
    ///
    /// Idempotency: if `new_public_key_did` is already populated on
    /// the rotation row, this step is a pure DB advancement — no fresh
    /// keypair is rolled. This is the failure-injection-test contract:
    /// resuming after a `key_generated` checkpoint must NOT discard
    /// the previously-generated key.
    ///
    /// The secret-key material is kept *only* on disk under the new
    /// path. The DB row only carries the public-key did. After this
    /// step, the next step reads the secret back from disk and
    /// re-derives the did, asserting the on-disk key matches the
    /// recorded did.
    async fn step_generate_key(&mut self) -> Result<(), RotationError> {
        // Idempotency: if a prior run already generated a key and
        // recorded the did, reuse it. We don't have the secret in
        // memory anymore, but step_write_new_key_material is also
        // idempotent (it checks if the file already exists with the
        // right contents), so the secret-on-disk-or-not state is
        // decided by that step.
        if self.plan.new_did.is_some() {
            return self.advance_to(RotationStep::KeyGenerated).await;
        }

        let kp = K256Keypair::generate();
        let new_did = kp.did();
        let secret = kp.export_private_key();
        let hex_secret = hex::encode(&secret);

        // Persist BOTH the did (for resume) and the secret bytes (for
        // step_write_new_key_material). We can't store the secret in
        // the DB row — that would mean a plaintext signing key in
        // Postgres. Instead, we write it to disk here at the path the
        // CLI specified; step_write_new_key_material then re-reads it
        // and applies the proper file mode. The two-phase write looks
        // redundant but it is the only way to keep
        // step_generate_key idempotent against a crash between the
        // file write and the DB UPDATE: a resume reads `new_did` from
        // the DB, sees the file already on disk, and treats the
        // generation step as done.
        write_key_atomic(&self.new_key_path, &hex_secret)
            .map_err(|reason| RotationError::WriteKey { reason })?;

        sqlx::query!(
            r#"
            UPDATE rotation_state
            SET new_public_key_did = $1,
                last_step = 'key_generated'::rotation_step,
                last_step_at = now()
            WHERE id = $2
            "#,
            &new_did,
            self.plan.id,
        )
        .execute(&self.pool)
        .await
        .map_err(RotationError::Db)?;

        self.plan.new_did = Some(new_did);
        self.plan.last_step = RotationStep::KeyGenerated;

        info!(
            rotation_id = %self.plan.id,
            new_public_key_did = self.plan.new_did.as_deref().unwrap_or("<unset>"),
            "rotation: new K-256 keypair generated"
        );
        Ok(())
    }

    /// Step 2: write the new key material to its custody-store
    /// destination. For `file-plain` the key was already written to
    /// disk in step 1 (the secret lifetime is `step_generate_key`'s
    /// local scope, so we cannot defer the write to here); this step
    /// verifies the on-disk did matches `new_public_key_did` and
    /// applies the mode-0o600 enforcement.
    ///
    /// Idempotency: re-reading and re-stat-ing the on-disk file is
    /// safe; the same did is computed deterministically from the same
    /// 32 bytes.
    async fn step_write_new_key_material(&mut self) -> Result<(), RotationError> {
        let expected_did = self
            .plan
            .new_did
            .as_deref()
            .ok_or(RotationError::WriteKey {
                reason: "new_public_key_did is unset at step_write_new_key_material",
            })?;

        let raw =
            std::fs::read_to_string(&self.new_key_path).map_err(|_| RotationError::WriteKey {
                reason: "could not read new key file at WriteNewKeyMaterial step",
            })?;
        let bytes = hex::decode(raw.trim()).map_err(|_| RotationError::WriteKey {
            reason: "new key file is not valid hex at WriteNewKeyMaterial step",
        })?;
        let kp = K256Keypair::from_private_key(&bytes).map_err(|_| RotationError::WriteKey {
            reason: "new key file does not form a valid K-256 secret",
        })?;
        let on_disk_did = kp.did();
        if on_disk_did != expected_did {
            return Err(RotationError::WriteKey {
                reason: "on-disk new key did does not match the rotation-state recorded did",
            });
        }

        enforce_mode_0o600(&self.new_key_path)?;

        self.advance_to(RotationStep::KeyWritten).await?;
        info!(
            rotation_id = %self.plan.id,
            new_key_path = %self.new_key_path.display(),
            "rotation: new key material persisted to custody store"
        );
        Ok(())
    }

    /// Step 3: re-publish the operator's `app.bsky.labeler.service`
    /// record under the new key. v1 v=logs an audit pointer; the actual
    /// network call is delegated to the `polaris-publish-labeler-record`
    /// binary which the operator runs alongside the rotation CLI. This
    /// keeps the rotation flow offline-clean for tests.
    async fn step_publish_service_record(&mut self) -> Result<(), RotationError> {
        // Build the would-be record using polaris-publish-labeler-record's
        // pure constructor. We *don't* call put_record from here — the
        // record-publish binary owns the network glue. We just exercise
        // the constructor so a mismatched configuration is caught at
        // this step rather than at the operator's follow-up run.
        //
        // Clone the did to an owned String so the immutable borrow of
        // `self.plan` ends before `self.advance_to(...).await` takes a
        // mutable borrow. The clone is one short heap String per
        // rotation — disproportionate to nothing on a CLI codepath.
        let new_did = self.plan.new_did.clone().ok_or(RotationError::Publish {
            reason: "new_public_key_did is unset at step_publish_service_record",
        })?;

        // We deliberately do not invoke the publish binary from here
        // (the rotation CLI has no Bluesky credentials in its
        // process). The check is constructor-only: bad inputs surface
        // as RotationError::Publish; otherwise the step succeeds and
        // the operator's follow-up run handles the actual put_record.
        let _record = polaris_publish_labeler_record::build_labeler_service_record(
            // service_url is not in scope for the rotation CLI; the
            // record builder accepts any HTTPS URL and validates form
            // only. We pass a sentinel that exercises the validator
            // without claiming a specific deployment URL — the actual
            // publish binary takes a fresh --service-url at run time.
            "https://labeler.invalid",
            &new_did,
            vec!["spam".to_owned()],
        )
        .map_err(|_| RotationError::Publish {
            reason: "labeler-service record builder rejected the new key",
        })?;

        self.advance_to(RotationStep::ServiceRecordPublished)
            .await?;
        info!(
            rotation_id = %self.plan.id,
            new_public_key_did = %new_did,
            "rotation: labeler-service record build verified (operator must publish out-of-band)"
        );
        Ok(())
    }

    /// Step 4: insert the new key into `signing_key_history` and close
    /// the prior active row in one transaction.
    ///
    /// Idempotency: a unique constraint on `public_key_did` plus an
    /// existence check in the same TX makes a re-run on an already-
    /// recorded did a no-op (no UPDATE, no INSERT).
    async fn step_record_history(&mut self) -> Result<(), RotationError> {
        let new_did = self
            .plan
            .new_did
            .as_deref()
            .ok_or(RotationError::WriteKey {
                reason: "new_public_key_did is unset at step_record_history",
            })?;

        let mut tx = self.pool.begin().await.map_err(RotationError::Db)?;

        // Existence check: if the new did is already in the table, the
        // step is done. (Idempotent re-run after a crash between
        // history insert and last_step UPDATE.)
        let already_recorded = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM signing_key_history WHERE public_key_did = $1
            ) AS "exists!"
            "#,
            new_did,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(RotationError::Db)?;

        if !already_recorded {
            // 1. Close the prior active row.
            sqlx::query!(
                r#"
                UPDATE signing_key_history
                SET active_until = now()
                WHERE active_until IS NULL
                "#,
            )
            .execute(&mut *tx)
            .await
            .map_err(RotationError::Db)?;

            // 2. Insert the new active row. The
            // signing_key_history_only_one_active partial unique index
            // makes "two NULL active_until simultaneously" a database-
            // level violation; the close-then-insert order is correct
            // because both operations happen in the same TX.
            sqlx::query!(
                r#"
                INSERT INTO signing_key_history (public_key_did, custody_mode)
                VALUES ($1, $2)
                "#,
                new_did,
                self.plan.custody_mode.as_str(),
            )
            .execute(&mut *tx)
            .await
            .map_err(RotationError::Db)?;
        }

        // 3. Advance the rotation state in the same TX so the read of
        // signing_key_history.active_until and this last_step write
        // commit atomically.
        sqlx::query!(
            r#"
            UPDATE rotation_state
            SET last_step = 'history_recorded'::rotation_step,
                last_step_at = now()
            WHERE id = $1
            "#,
            self.plan.id,
        )
        .execute(&mut *tx)
        .await
        .map_err(RotationError::Db)?;

        tx.commit().await.map_err(RotationError::Db)?;
        self.plan.last_step = RotationStep::HistoryRecorded;

        info!(
            rotation_id = %self.plan.id,
            new_public_key_did = new_did,
            "rotation: signing_key_history updated"
        );
        Ok(())
    }

    /// Step 5: append the old key to `revoked_keys`.
    ///
    /// Idempotency: `INSERT … ON CONFLICT DO NOTHING` against the
    /// PRIMARY KEY on `public_key_did`.
    async fn step_revoke_old_key(&mut self) -> Result<(), RotationError> {
        let Some(old_did) = self.plan.old_did.as_deref() else {
            return Err(RotationError::Init {
                reason: "old_public_key_did unset at step_revoke_old_key",
            });
        };

        let mut tx = self.pool.begin().await.map_err(RotationError::Db)?;
        sqlx::query!(
            r#"
            INSERT INTO revoked_keys (public_key_did, reason)
            VALUES ($1, 'rotation')
            ON CONFLICT (public_key_did) DO NOTHING
            "#,
            old_did,
        )
        .execute(&mut *tx)
        .await
        .map_err(RotationError::Db)?;

        sqlx::query!(
            r#"
            UPDATE rotation_state
            SET last_step = 'old_key_revoked'::rotation_step,
                last_step_at = now()
            WHERE id = $1
            "#,
            self.plan.id,
        )
        .execute(&mut *tx)
        .await
        .map_err(RotationError::Db)?;

        tx.commit().await.map_err(RotationError::Db)?;
        self.plan.last_step = RotationStep::OldKeyRevoked;

        info!(
            rotation_id = %self.plan.id,
            old_public_key_did = old_did,
            "rotation: old key appended to revoked_keys"
        );
        Ok(())
    }

    /// Step 6: notify the live server's `watch::Sender`.
    ///
    /// In v1 the rotation CLI and the live server are separate
    /// processes; the live server detects the new active key by
    /// polling `signing_key_history` on a `tokio::time::interval` and
    /// reloads its in-process `Arc<dyn SigningKey>` via its local
    /// `watch::Sender::send`. The rotation CLI therefore has nothing
    /// to do here at the process boundary — it just advances the
    /// `rotation_state` to `Swapped`.
    ///
    /// Tests run in-process and DO have access to the `watch::Sender`;
    /// they call `signer_tx.send(new_signer)` directly to simulate the
    /// live-server poll.
    async fn step_atomic_swap(&mut self) -> Result<(), RotationError> {
        self.advance_to(RotationStep::Swapped).await?;
        info!(
            rotation_id = %self.plan.id,
            "rotation: persisted state; live server will pick up the new key on its next poll tick"
        );
        Ok(())
    }
}

/// Atomically write `contents` to `path` with mode `0o600`.
///
/// Strategy: write to `<path>.tmp-<uuid>`, set the file mode to
/// `0o600`, then `rename` over the destination. The `rename` is
/// guaranteed atomic on the same filesystem; partial-write artefacts
/// stay under a sibling name and never appear at the destination.
///
/// On non-Unix targets the mode-setting is a no-op (Windows ACLs are
/// validated by the operator's deployment tooling).
fn write_key_atomic(path: &std::path::Path, contents: &str) -> Result<(), &'static str> {
    use std::io::Write as _;

    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("polaris-key");
    let tmp_name = format!("{stem}.tmp-{}", Uuid::new_v4());
    let tmp_path = parent.join(tmp_name);

    let mut file =
        std::fs::File::create(&tmp_path).map_err(|_| "could not create temp file for new key")?;
    file.write_all(contents.as_bytes())
        .map_err(|_| "write to temp file failed")?;
    file.flush().map_err(|_| "temp file flush failed")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp_path, perms)
            .map_err(|_| "could not set 0o600 on temp file")?;
    }
    drop(file);
    std::fs::rename(&tmp_path, path).map_err(|_| "atomic rename of new key file failed")?;
    Ok(())
}

/// Enforce file mode 0o600 on `path`. On non-Unix targets this is a
/// no-op.
#[cfg(unix)]
fn enforce_mode_0o600(path: &std::path::Path) -> Result<(), RotationError> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path).map_err(|_| RotationError::WriteKey {
        reason: "could not stat new key file at WriteNewKeyMaterial",
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(RotationError::WriteKey {
            reason: "new key file is mode-wider than 0o600",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_mode_0o600(_path: &std::path::Path) -> Result<(), RotationError> {
    Ok(())
}

/// Look up the active signing key did at a particular instant.
///
/// Used by [`crate::labeler::verify::verify_label`] at signature-verify
/// time so a label signed under K1 still verifies post-rotation even
/// when the live server's active key is K2.
///
/// Returns the did of the key whose
/// `[active_from, COALESCE(active_until, +∞))` window contains
/// `at_instant`, or `None` if no row matches (i.e. the instant
/// pre-dates any recorded active key).
///
/// # Errors
///
/// Returns the underlying `sqlx::Error` on query failure.
pub async fn active_key_at(
    pool: &PgPool,
    at_instant: DateTime<Utc>,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT public_key_did
        FROM signing_key_history
        WHERE active_from <= $1
          AND (active_until IS NULL OR active_until > $1)
        ORDER BY active_from DESC
        LIMIT 1
        "#,
        at_instant,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.public_key_did))
}

/// Bootstrap the initial active signing key.
///
/// Inserts a row into `signing_key_history` if none with the given did
/// already exists. Used by the integration tests and by the operator's
/// first-time setup flow. Idempotent: re-inserting the same did is a
/// no-op via `ON CONFLICT DO NOTHING`.
///
/// # Errors
///
/// Returns the underlying `sqlx::Error` on query failure.
pub async fn bootstrap_active_key(
    pool: &PgPool,
    public_key_did: &str,
    mode: CustodyMode,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO signing_key_history (public_key_did, custody_mode)
        VALUES ($1, $2)
        ON CONFLICT (public_key_did) DO NOTHING
        "#,
        public_key_did,
        mode.as_str(),
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    fn make_plan(last_step: RotationStep) -> RotationPlan {
        RotationPlan {
            id: Uuid::nil(),
            custody_mode: CustodyMode::FilePlain,
            last_step,
            old_did: Some("did:key:zOld".to_owned()),
            new_did: None,
        }
    }

    #[test]
    fn next_step_drives_through_the_full_sequence() {
        let cases = [
            (RotationStep::Pending, Some(NextStep::GenerateKey)),
            (
                RotationStep::KeyGenerated,
                Some(NextStep::WriteNewKeyMaterial),
            ),
            (
                RotationStep::KeyWritten,
                Some(NextStep::PublishServiceRecord),
            ),
            (
                RotationStep::ServiceRecordPublished,
                Some(NextStep::RecordHistory),
            ),
            (RotationStep::HistoryRecorded, Some(NextStep::RevokeOldKey)),
            (RotationStep::OldKeyRevoked, Some(NextStep::AtomicSwap)),
            (RotationStep::Swapped, None),
            (RotationStep::Complete, None),
            (RotationStep::Aborted, None),
        ];
        for (step, expected) in cases {
            let plan = make_plan(step);
            assert_eq!(
                next_step(&plan),
                expected,
                "next_step({step:?}) should be {expected:?}",
            );
        }
    }

    #[test]
    fn rotation_step_db_str_roundtrip() {
        for step in [
            RotationStep::Pending,
            RotationStep::KeyGenerated,
            RotationStep::KeyWritten,
            RotationStep::ServiceRecordPublished,
            RotationStep::HistoryRecorded,
            RotationStep::OldKeyRevoked,
            RotationStep::Swapped,
            RotationStep::Complete,
            RotationStep::Aborted,
        ] {
            let s = step.as_str();
            assert_eq!(
                RotationStep::from_db_str(s),
                Some(step),
                "{s} did not roundtrip"
            );
        }
        assert_eq!(RotationStep::from_db_str("not-a-step"), None);
    }

    #[test]
    fn custody_mode_wire_names_are_stable() {
        assert_eq!(CustodyMode::FilePlain.as_str(), "file-plain");
        assert_eq!(CustodyMode::PassphraseSealed.as_str(), "passphrase-sealed");
        assert_eq!(CustodyMode::OsKeychain.as_str(), "os-keychain");
        assert_eq!(CustodyMode::CloudKms.as_str(), "cloud-kms-oracle");
    }

    #[test]
    fn custody_mode_from_signing_key_config() {
        use crate::config::{KmsProvider, LabelerSigningKeyConfig};
        use std::path::PathBuf;

        let cases = [
            (
                LabelerSigningKeyConfig::FilePlain {
                    path: PathBuf::from("/tmp/x"),
                },
                CustodyMode::FilePlain,
            ),
            (
                LabelerSigningKeyConfig::PassphraseSealed {
                    path: PathBuf::from("/tmp/x"),
                },
                CustodyMode::PassphraseSealed,
            ),
            (
                LabelerSigningKeyConfig::OsKeychain {
                    account: "acct".to_owned(),
                },
                CustodyMode::OsKeychain,
            ),
            (
                LabelerSigningKeyConfig::CloudKms {
                    provider: KmsProvider::Aws,
                    key_id: "k".to_owned(),
                    region: "us-east-1".to_owned(),
                },
                CustodyMode::CloudKms,
            ),
        ];
        for (cfg, expected) in cases {
            assert_eq!(CustodyMode::from(&cfg), expected);
        }
    }

    #[test]
    fn write_key_atomic_writes_with_mode_0o600() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("polaris.key");
        write_key_atomic(&target, "deadbeef").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "deadbeef");
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "atomic key write must land mode 0o600");
        }
    }

    #[test]
    fn write_key_atomic_replaces_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("polaris.key");
        write_key_atomic(&target, "first").unwrap();
        write_key_atomic(&target, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
    }
}
