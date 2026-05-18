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
use zeroize::Zeroize as _;

use crate::audit::{AuditEvent, AuditLog};
use crate::config::{KmsProvider, LabelerSigningKeyConfig};
use crate::labeler::signer::passphrase_sealed::PassphraseSealedSigner;

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

    /// The CLI was invoked with `--mode <m>` but the implementation
    /// of `<m>` is still a stub. After #64 only the un-wired cloud-KMS
    /// providers (GCP / Azure) raise this; passphrase-sealed,
    /// os-keychain, and AWS-cloud-kms are wired end-to-end.
    #[error("rotation mode {mode:?} is not yet wired end-to-end")]
    Unsupported {
        /// The mode (or provider variant) the operator asked for.
        mode: &'static str,
    },
}

/// Per-mode parameters the rotation state machine needs at
/// `step_write_new_key_material` time.
///
/// `RotationContext` carries one of these — the variant must match
/// `plan.custody_mode`. The state machine reads this carrier inside the
/// `WriteNewKeyMaterial` dispatch to thread mode-specific runtime
/// inputs (passphrase / account / KMS region) into the helper functions.
///
/// `FilePlain` carries no params (the staged plaintext on `new_key_path`
/// is all the file-plain write path needs). The other variants carry
/// the inputs the operator supplies via env vars or CLI flags.
#[derive(Debug, Clone)]
pub enum RotationCustodyParams {
    /// File-plain — no extra params beyond the staged path.
    FilePlain,
    /// Passphrase-sealed — operator-supplied unseal passphrase.
    ///
    /// The string holds the passphrase **only for the duration of the
    /// rotation step**; the helper consumes it, derives the KEK, and
    /// drops the buffer immediately. See
    /// [`PassphraseSealedSigner::write_sealed`] for the seal contract.
    PassphraseSealed {
        /// Passphrase used to derive the AES-256-GCM KEK.
        passphrase: String,
    },
    /// OS keychain — operator-configured account name.
    OsKeychain {
        /// Account name under the `polaris.labeler` service. Mirrors
        /// `LabelerSigningKeyConfig::OsKeychain.account`.
        account: String,
    },
    /// Cloud KMS oracle — provider, region, and the existing alias the
    /// rotation re-points at the freshly-created KMS key.
    CloudKms {
        /// Cloud-KMS provider. Only [`KmsProvider::Aws`] is wired today.
        provider: KmsProvider,
        /// Region of both the alias and the new key.
        region: String,
        /// Existing alias name (e.g. `"alias/polaris-labeler"`). After
        /// rotation, this alias points at the freshly-created key id.
        current_alias: String,
    },
}

impl RotationCustodyParams {
    /// Custody mode this params variant matches.
    #[must_use]
    pub const fn mode(&self) -> CustodyMode {
        match self {
            Self::FilePlain => CustodyMode::FilePlain,
            Self::PassphraseSealed { .. } => CustodyMode::PassphraseSealed,
            Self::OsKeychain { .. } => CustodyMode::OsKeychain,
            Self::CloudKms { .. } => CustodyMode::CloudKms,
        }
    }
}

/// Runtime side of a rotation: the DB pool, the plan, and the
/// per-mode parameters the steps need.
///
/// `new_key_path` is the *staging* path: every mode generates a fresh
/// K-256 keypair locally first (so `step_generate_key` stays mode-
/// agnostic), then `step_write_new_key_material` transports the bytes
/// into the configured custody store. For `file-plain` the staging
/// path *is* the final destination; for the other three modes the
/// staged file is consumed by `step_write_new_key_material` and removed
/// afterwards.
#[derive(Debug)]
pub struct RotationContext {
    pool: PgPool,
    plan: RotationPlan,
    /// Filesystem path the staged plaintext keypair is written to. For
    /// `file-plain` this is the final destination; for the other modes
    /// it is a temporary handoff between `step_generate_key` (writes)
    /// and `step_write_new_key_material` (consumes + deletes).
    new_key_path: PathBuf,
    /// Per-mode params the dispatch in `step_write_new_key_material`
    /// reads. Must match `plan.custody_mode` — `new_rotation` /
    /// `resume` reject mismatches at construction time.
    custody_params: RotationCustodyParams,
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
    /// `params` must carry a variant matching `mode`; the carrier feeds
    /// the per-mode dispatch in `step_write_new_key_material`.
    ///
    /// # Errors
    ///
    /// - [`RotationError::Init`] when the DB has no active key or when
    ///   `params` does not match `mode`.
    /// - [`RotationError::Db`] for any underlying SQL error.
    pub async fn new_rotation(
        pool: PgPool,
        mode: CustodyMode,
        new_key_path: PathBuf,
        params: RotationCustodyParams,
    ) -> Result<Self, RotationError> {
        if params.mode() != mode {
            return Err(RotationError::Init {
                reason: "RotationCustodyParams variant does not match the CustodyMode argument",
            });
        }
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
            custody_params: params,
        })
    }

    /// Reload a rotation from its `rotation_state.id` (the `--resume`
    /// path).
    ///
    /// `params` must carry a variant matching the CLI's `cli_mode` —
    /// the `rotation_state` row carries the mode itself (the on-the-
    /// wire string) but not the per-mode runtime inputs, so the caller
    /// re-supplies them on resume.
    ///
    /// # Errors
    ///
    /// - [`RotationError::Init`] when the row is missing, the custody
    ///   mode column does not match the CLI's `--mode`, the params
    ///   variant does not match the CLI's `--mode`, or the enum
    ///   decoding fails.
    /// - [`RotationError::Db`] for any underlying SQL error.
    pub async fn resume(
        pool: PgPool,
        rotation_id: Uuid,
        cli_mode: CustodyMode,
        params: RotationCustodyParams,
    ) -> Result<Self, RotationError> {
        if params.mode() != cli_mode {
            return Err(RotationError::Init {
                reason: "RotationCustodyParams variant does not match the --mode argument",
            });
        }
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
            custody_params: params,
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
        // All four custody modes flow through the same transition
        // table; the per-mode work happens inside
        // `step_write_new_key_material`'s dispatch. The previous
        // `FilePlain`-only gate was lifted as part of #64 — see the
        // dispatch site for the per-mode write paths.
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
    /// destination.
    ///
    /// `step_generate_key` (step 1) writes a hex-encoded plaintext
    /// keypair to `new_key_path` regardless of custody mode — the
    /// staging file is the bridge between the in-memory keypair and
    /// the per-mode persistence. This step dispatches on
    /// `plan.custody_mode` and transports the staged bytes into the
    /// configured custody store:
    ///
    /// | mode               | write path                                         |
    /// |--------------------|----------------------------------------------------|
    /// | `file-plain`       | verify + enforce 0o600 on `new_key_path`           |
    /// | `passphrase-sealed`| seal + atomic-rename the sealed blob at `new_key_path` |
    /// | `os-keychain`      | keyring `set_password` + delete staged file        |
    /// | `cloud-kms-oracle` | KMS create + alias swap; delete staged file        |
    ///
    /// Idempotency: every per-mode helper is idempotent (sealed re-
    /// write is byte-identical for the same secret+passphrase modulo
    /// salt/nonce, keyring `set_password` overwrites, alias swap is
    /// a no-op when it already points at the new key id).
    async fn step_write_new_key_material(&mut self) -> Result<(), RotationError> {
        let expected_did = self
            .plan
            .new_did
            .as_deref()
            .ok_or(RotationError::WriteKey {
                reason: "new_public_key_did is unset at step_write_new_key_material",
            })?;

        // Read + validate the staged plaintext once. Each per-mode
        // helper then consumes the resulting `K256Keypair` instead of
        // re-decoding the file. The mode-0o600 check still runs for
        // `FilePlain`; the other modes either re-seal-then-replace
        // (passphrase-sealed) or move the secret off disk entirely
        // (os-keychain, cloud-kms-oracle) — both safer postures than
        // the staged-plaintext intermediate.
        let raw =
            std::fs::read_to_string(&self.new_key_path).map_err(|_| RotationError::WriteKey {
                reason: "could not read new key file at WriteNewKeyMaterial step",
            })?;
        let mut secret_bytes = hex::decode(raw.trim()).map_err(|_| RotationError::WriteKey {
            reason: "new key file is not valid hex at WriteNewKeyMaterial step",
        })?;
        let kp =
            K256Keypair::from_private_key(&secret_bytes).map_err(|_| RotationError::WriteKey {
                reason: "new key file does not form a valid K-256 secret",
            })?;
        let on_disk_did = kp.did();
        if on_disk_did != expected_did {
            // Zeroise the staged secret before bailing — we read it
            // into a heap Vec and we own it.
            secret_bytes.zeroize();
            return Err(RotationError::WriteKey {
                reason: "on-disk new key did does not match the rotation-state recorded did",
            });
        }

        match &self.custody_params {
            RotationCustodyParams::FilePlain => {
                // File-plain: the staged file IS the custody store.
                // Only enforce 0o600 — `step_generate_key` already
                // wrote with mode 0o600 via the atomic-rename helper.
                enforce_mode_0o600(&self.new_key_path)?;
            }
            RotationCustodyParams::PassphraseSealed { passphrase } => {
                let secret_arr: &[u8; 32] =
                    secret_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| RotationError::WriteKey {
                            reason: "staged K-256 secret is not exactly 32 bytes",
                        })?;
                write_passphrase_sealed_key(&self.new_key_path, secret_arr, passphrase)?;
            }
            RotationCustodyParams::OsKeychain { account } => {
                let hex_secret = hex::encode(&secret_bytes);
                write_os_keychain_key(account, &hex_secret)?;
                // Remove the staged plaintext — the canonical store is
                // now the OS keychain. Failure to delete is logged but
                // not fatal: a stale file on disk is recoverable, but
                // a successful keychain write must not be unwound.
                if let Err(e) = std::fs::remove_file(&self.new_key_path) {
                    tracing::warn!(
                        new_key_path = %self.new_key_path.display(),
                        error = ?e,
                        "rotation: keychain write succeeded but staged plaintext could not be removed",
                    );
                }
            }
            RotationCustodyParams::CloudKms {
                provider,
                region,
                current_alias,
            } => {
                let new_key_id = write_cloud_kms_key(*provider, region, current_alias)?;
                // The new key id ends up on the rotation row's
                // `error` column-equivalent — currently nowhere, since
                // the schema only carries `new_public_key_did`. For
                // forward-compat we log it; a follow-up will add a
                // `new_kms_key_id` column.
                info!(
                    rotation_id = %self.plan.id,
                    new_kms_key_id = %new_key_id,
                    "rotation: cloud-kms-oracle new key created and alias swapped"
                );
                if let Err(e) = std::fs::remove_file(&self.new_key_path) {
                    tracing::warn!(
                        new_key_path = %self.new_key_path.display(),
                        error = ?e,
                        "rotation: KMS rotation succeeded but staged plaintext could not be removed",
                    );
                }
            }
        }

        secret_bytes.zeroize();

        self.advance_to(RotationStep::KeyWritten).await?;
        info!(
            rotation_id = %self.plan.id,
            mode = self.plan.custody_mode.as_str(),
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

        // 4. Audit-log append in the same TX (issue #35;
        // design.md §6 + §9). The new key going live is the
        // audit-relevant boundary; we record it as `key.rotate` with
        // both the outgoing and incoming dids in the payload so an
        // auditor can reconstruct the active-key timeline from the
        // audit log alone.
        let audit_payload = serde_json::json!({
            "rotation_id": self.plan.id,
            "old_did": self.plan.old_did,
            "new_did": new_did,
            "custody_mode": self.plan.custody_mode.as_str(),
        });
        AuditLog::record(
            &mut tx,
            AuditEvent {
                actor: "system".to_owned(),
                kind: "key.rotate".to_owned(),
                payload: audit_payload,
            },
        )
        .await
        .map_err(audit_to_rotation_err)?;

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

/// Map an audit-log append failure into a [`RotationError`].
///
/// `AuditError::Db` unwraps to a [`RotationError::Db`] so SQLSTATE
/// routing (chain-break P0001, etc.) flows up to the caller without an
/// extra wrapping layer. Encoding failures are treated as a DB-class
/// failure with a synthetic message because they indicate a payload
/// that should never have been built in the first place (the rotation
/// payload is constructed from typed fields).
fn audit_to_rotation_err(err: crate::audit::AuditError) -> RotationError {
    match err {
        crate::audit::AuditError::Db(e) => RotationError::Db(e),
        crate::audit::AuditError::Encode { .. } | crate::audit::AuditError::HashMismatch { .. } => {
            RotationError::Init {
                reason: "audit-log payload encode or chain integrity check failed during rotation",
            }
        }
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

/// Write the new K-256 secret to `path` sealed under `passphrase`.
///
/// Calls [`PassphraseSealedSigner::write_sealed`] to produce the v1
/// AES-256-GCM-with-scrypt-KEK blob, then atomic-renames it into place
/// with mode `0o600`. The on-disk format is the exact format
/// [`PassphraseSealedSigner::from_path`] consumes — round-trip tested
/// in the passphrase-sealed unit tests.
///
/// # Errors
///
/// Returns [`RotationError::WriteKey`] on seal failure (in practice
/// unreachable for the hard-coded scrypt params; the typed error path
/// keeps the API uniform) or on filesystem write failure.
fn write_passphrase_sealed_key(
    path: &std::path::Path,
    secret: &[u8; 32],
    passphrase: &str,
) -> Result<(), RotationError> {
    let sealed = PassphraseSealedSigner::write_sealed(secret, passphrase).map_err(|_| {
        RotationError::WriteKey {
            reason: "passphrase-sealed seal step failed during rotation",
        }
    })?;
    write_bytes_atomic(path, &sealed).map_err(|reason| RotationError::WriteKey { reason })?;
    Ok(())
}

/// Write `keypair_hex` into the OS keychain under
/// `(KEYRING_SERVICE, account)`.
///
/// `keypair_hex` is the 64-char hex encoding of the raw 32-byte K-256
/// secret — the same format
/// [`crate::labeler::signer::os_keychain::OsKeychainSigner::from_account`]
/// reads back at signer-construction time. `keyring::Entry::set_password`
/// overwrites the existing entry when one is present, so re-running
/// this step on a partially-applied rotation is a no-op-or-overwrite.
///
/// # Errors
///
/// Returns [`RotationError::WriteKey`] on a keychain transport,
/// platform, or permission failure. The platform name is included so
/// an operator running on a host without a supported backend sees an
/// actionable message.
fn write_os_keychain_key(account: &str, keypair_hex: &str) -> Result<(), RotationError> {
    // Pin the service name to the signer module's constant so the
    // rotation write and the signer read agree on the keychain key.
    use crate::labeler::signer::os_keychain::KEYRING_SERVICE;

    let entry =
        keyring::Entry::new(KEYRING_SERVICE, account).map_err(|_| RotationError::WriteKey {
            reason: "os-keychain: could not address keychain entry for rotation write",
        })?;
    entry.set_password(keypair_hex).map_err(|_| {
        RotationError::WriteKey {
            reason: "os-keychain: could not store new key in OS keychain (platform / permission failure)",
        }
    })?;
    Ok(())
}

/// Create a new KMS keypair, point `current_alias` at it, return the
/// new key id.
///
/// Alias swap is the rotation primitive: callers (the polaris-backend
/// runtime, the labeler signer) address KMS via the *alias*, not the
/// raw key id. After this function returns, the alias resolves to the
/// freshly-created key; the old key id keeps existing in KMS (an
/// operator-side scheduled deletion is the recommended follow-up but
/// is intentionally not automated — KMS deletion is irreversible and
/// must remain a manual decision).
///
/// AWS KMS does not have a single "make me a new asymmetric signing
/// key" RPC that matches the architect pre-flight's
/// `generate_data_key_pair` exactly: that RPC is for *data* keys
/// (a fresh keypair *encrypted* by a CMK), which a labeler signer
/// cannot sign with directly. The right primitive for an asymmetric
/// signing key is `CreateKey` with `KeyUsage=SIGN_VERIFY` and
/// `KeySpec=ECC_SECG_P256K1`; that is what this function calls. The
/// alias swap (`UpdateAlias`) is the second leg. See the AWS KMS
/// developer guide on rotating asymmetric customer-managed keys for
/// background.
///
/// # Errors
///
/// - [`RotationError::Unsupported`] for the non-AWS `KmsProvider`
///   variants (Gcp / Azure), or when the `kms-integration` Cargo
///   feature is disabled (the AWS SDK is feature-gated).
/// - [`RotationError::WriteKey`] on a KMS RPC failure or missing key
///   id in the SDK response.
fn write_cloud_kms_key(
    provider: KmsProvider,
    region: &str,
    current_alias: &str,
) -> Result<String, RotationError> {
    match provider {
        KmsProvider::Aws => write_cloud_kms_key_aws(region, current_alias),
        KmsProvider::Gcp => write_cloud_kms_key_gcp(region, current_alias),
        KmsProvider::Azure => write_cloud_kms_key_azure(region, current_alias),
    }
}

#[cfg(feature = "kms-integration")]
fn write_cloud_kms_key_aws(region: &str, current_alias: &str) -> Result<String, RotationError> {
    use aws_config::BehaviorVersion;
    use aws_sdk_kms::Client;
    use aws_sdk_kms::types::{KeySpec, KeyUsageType};

    // The rotation CLI is not yet inside a tokio runtime when this
    // function runs (the CLI's `main` is `#[tokio::main]`, but the
    // step is invoked from a sync context within an async `run`).
    // Spin a short-lived runtime exclusively for the two KMS RPCs.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle: failed to spin a tokio runtime for KMS rotation",
        })?;

    let region_owned = region.to_owned();
    let alias_owned = current_alias.to_owned();

    rt.block_on(async move {
        let cfg = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region_owned))
            .load()
            .await;
        let client = Client::new(&cfg);

        // 1. CreateKey — make a fresh asymmetric K-256 signing key.
        let create_resp = client
            .create_key()
            .key_usage(KeyUsageType::SignVerify)
            .key_spec(KeySpec::EccSecgP256K1)
            .description("polaris labeler signing key (rotated)")
            .send()
            .await
            .map_err(|_| RotationError::WriteKey {
                reason: "cloud-kms-oracle: AWS KMS CreateKey RPC failed",
            })?;
        let new_key_id = create_resp
            .key_metadata()
            .map(|m| m.key_id().to_owned())
            .ok_or(RotationError::WriteKey {
                reason: "cloud-kms-oracle: AWS KMS CreateKey returned no key metadata",
            })?;

        // 2. UpdateAlias — atomically re-point the existing alias at
        // the new key id. UpdateAlias is the alias-swap primitive (a
        // single AWS-side mutation); CreateAlias would fail when the
        // alias already exists, which is precisely the rotation case.
        client
            .update_alias()
            .alias_name(alias_owned)
            .target_key_id(&new_key_id)
            .send()
            .await
            .map_err(|_| RotationError::WriteKey {
                reason: "cloud-kms-oracle: AWS KMS UpdateAlias RPC failed",
            })?;

        Ok::<String, RotationError>(new_key_id)
    })
}

#[cfg(not(feature = "kms-integration"))]
fn write_cloud_kms_key_aws(_region: &str, _current_alias: &str) -> Result<String, RotationError> {
    Err(RotationError::Unsupported {
        mode: "cloud-kms-oracle/aws (requires `kms-integration` cargo feature)",
    })
}

// ── GCP cloud-KMS rotation ──────────────────────────────────────────
//
// GCP Cloud KMS rotation has a different shape than AWS aliases:
// each `CryptoKey` resource owns a numbered series of
// `CryptoKeyVersion`s, and the `primary` version is what `sign` /
// `getPublicKey` calls dispatch to. Rotation is therefore:
//
//   1. `POST projects/.../cryptoKeys/<key>/cryptoKeyVersions`
//      — creates a new version under the same key (the key's
//      algorithm is fixed at create time, so the new version
//      inherits EC_SIGN_SECP256K1_SHA256).
//   2. `POST projects/.../cryptoKeys/<key>:updatePrimaryVersion`
//      — atomically swaps `primary` to the new version's id.
//
// `current_alias` for the GCP provider carries the full CryptoKey
// resource name: `projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>`.
// `region` is informational (the location is already in the resource
// name); we accept it for API symmetry with AWS but don't otherwise
// consume it.
//
// Auth: GCP requires an OAuth2 access token. We read the operator's
// service-account JSON key from the path in `GCP_SERVICE_ACCOUNT_JSON`,
// sign a JWT with the embedded RSA key (RS256), and exchange at
// `oauth2.googleapis.com/token` for a token scoped to `cloudkms`.

/// GCP Cloud KMS REST endpoint root.
#[cfg(feature = "kms-integration")]
const GCP_KMS_BASE: &str = "https://cloudkms.googleapis.com/v1";

/// GCP `OAuth2` token-exchange endpoint.
#[cfg(feature = "kms-integration")]
const GCP_OAUTH_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Cloud KMS `OAuth2` scope.
#[cfg(feature = "kms-integration")]
const GCP_KMS_SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";

#[cfg(feature = "kms-integration")]
#[allow(
    clippy::too_many_lines,
    reason = "GCP rotation has three sequential REST calls (token-exchange, create-version, \
              update-primary) plus their failure paths; folding into helpers would push the \
              token + key-resource string lifetimes across boundaries with no readability win."
)]
fn write_cloud_kms_key_gcp(region: &str, current_alias: &str) -> Result<String, RotationError> {
    let _ = region; // accepted for API symmetry; location is in `current_alias`.

    // Service-account JSON key path: env-supplied so the operator's
    // credentials never enter the binary. The file is read at
    // rotation time, parsed, and the in-memory copy is dropped at the
    // end of this function.
    let sa_path =
        std::env::var("GCP_SERVICE_ACCOUNT_JSON").map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: GCP_SERVICE_ACCOUNT_JSON env var not set",
        })?;
    let sa_json = std::fs::read_to_string(&sa_path).map_err(|_| RotationError::WriteKey {
        reason: "cloud-kms-oracle/gcp: cannot read GCP service-account JSON file",
    })?;
    let sa: GcpServiceAccount =
        serde_json::from_str(&sa_json).map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: service-account JSON did not parse",
        })?;

    let key_resource = current_alias.to_owned();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: failed to spin a tokio runtime for KMS rotation",
        })?;

    rt.block_on(async move {
        let access_token = gcp_exchange_jwt_for_token(&sa).await?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| RotationError::WriteKey {
                reason: "cloud-kms-oracle/gcp: failed to build HTTP client",
            })?;

        // 1. POST .../cryptoKeyVersions — creates a new version under
        //    the existing CryptoKey, inheriting the key's algorithm.
        let create_url = format!("{GCP_KMS_BASE}/{key_resource}/cryptoKeyVersions");
        let create_resp = client
            .post(&create_url)
            .bearer_auth(&access_token)
            .header("Content-Type", "application/json")
            // GCP accepts an empty JSON body — the parent key's
            // algorithm defines the new version's algorithm. Sending
            // an explicit `{}` keeps the request length deterministic.
            .body("{}")
            .send()
            .await
            .map_err(|_| RotationError::WriteKey {
                reason: "cloud-kms-oracle/gcp: createVersion HTTP failed",
            })?;
        if !create_resp.status().is_success() {
            tracing::warn!(
                status = %create_resp.status(),
                "cloud-kms-oracle/gcp: createVersion returned non-2xx",
            );
            return Err(RotationError::WriteKey {
                reason: "cloud-kms-oracle/gcp: createVersion returned non-2xx",
            });
        }
        let create_body: serde_json::Value =
            create_resp
                .json()
                .await
                .map_err(|_| RotationError::WriteKey {
                    reason: "cloud-kms-oracle/gcp: createVersion response JSON decode failed",
                })?;
        let new_version_resource = create_body
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or(RotationError::WriteKey {
                reason: "cloud-kms-oracle/gcp: createVersion response missing `name`",
            })?
            .to_owned();
        // Pull the trailing "/cryptoKeyVersions/<id>" segment so we
        // can pass just the version id to updatePrimaryVersion.
        let version_id = new_version_resource
            .rsplit('/')
            .next()
            .ok_or(RotationError::WriteKey {
                reason: "cloud-kms-oracle/gcp: createVersion `name` is malformed",
            })?
            .to_owned();

        // 2. POST .../cryptoKeys/<key>:updatePrimaryVersion — atomic
        //    swap of the `primary` pointer on the parent key.
        let update_url = format!("{GCP_KMS_BASE}/{key_resource}:updatePrimaryVersion");
        let update_body = serde_json::json!({ "cryptoKeyVersionId": version_id });
        let update_resp = client
            .post(&update_url)
            .bearer_auth(&access_token)
            .header("Content-Type", "application/json")
            .body(update_body.to_string())
            .send()
            .await
            .map_err(|_| RotationError::WriteKey {
                reason: "cloud-kms-oracle/gcp: updatePrimaryVersion HTTP failed",
            })?;
        if !update_resp.status().is_success() {
            tracing::warn!(
                status = %update_resp.status(),
                "cloud-kms-oracle/gcp: updatePrimaryVersion returned non-2xx",
            );
            return Err(RotationError::WriteKey {
                reason: "cloud-kms-oracle/gcp: updatePrimaryVersion returned non-2xx",
            });
        }

        Ok(new_version_resource)
    })
}

#[cfg(not(feature = "kms-integration"))]
fn write_cloud_kms_key_gcp(_region: &str, _current_alias: &str) -> Result<String, RotationError> {
    Err(RotationError::Unsupported {
        mode: "cloud-kms-oracle/gcp (requires `kms-integration` cargo feature)",
    })
}

/// Minimal subset of a GCP service-account JSON we need for the
/// JWT-signed token exchange.
#[cfg(feature = "kms-integration")]
#[derive(Debug, serde::Deserialize)]
#[allow(
    non_snake_case,
    reason = "field names mirror the GCP service-account JSON shape verbatim"
)]
struct GcpServiceAccount {
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}

#[cfg(feature = "kms-integration")]
async fn gcp_exchange_jwt_for_token(sa: &GcpServiceAccount) -> Result<String, RotationError> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: system clock before UNIX epoch",
        })?
        .as_secs();

    let token_uri = sa
        .token_uri
        .clone()
        .unwrap_or_else(|| GCP_OAUTH_TOKEN_ENDPOINT.to_owned());

    // JWT assertion: GCP's service-account exchange spec at
    // https://developers.google.com/identity/protocols/oauth2/service-account
    let claims = serde_json::json!({
        "iss":   sa.client_email,
        "scope": GCP_KMS_SCOPE,
        "aud":   token_uri,
        "iat":   now,
        "exp":   now + 3600,
    });
    let encoding_key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|_| {
        RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: service-account private_key did not parse as PEM RSA",
        }
    })?;
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_owned());
    let assertion =
        encode(&header, &claims, &encoding_key).map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: JWT assertion sign failed",
        })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: failed to build OAuth2 HTTP client",
        })?;
    let resp = client
        .post(&token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ])
        .send()
        .await
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: OAuth2 token exchange HTTP failed",
        })?;
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            "cloud-kms-oracle/gcp: OAuth2 token exchange returned non-2xx",
        );
        return Err(RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: OAuth2 token exchange returned non-2xx",
        });
    }
    let body: serde_json::Value = resp.json().await.map_err(|_| RotationError::WriteKey {
        reason: "cloud-kms-oracle/gcp: OAuth2 token-exchange JSON decode failed",
    })?;
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(RotationError::WriteKey {
            reason: "cloud-kms-oracle/gcp: OAuth2 token-exchange response missing access_token",
        })
}

// ── Azure cloud-KMS rotation ────────────────────────────────────────
//
// Azure Key Vault Keys have built-in versioning: every call to
// `createKey` on an existing key name produces a new version, and the
// "active" version is automatically the most recently created. There
// is no separate alias-swap call — one POST does the whole rotation.
//
// `current_alias` for the Azure provider carries the Key Vault key
// resource shape: `https://<vault>.vault.azure.net/keys/<key-name>`.
// The function appends `/create?api-version=7.4` and POSTs the
// algorithm + key-ops payload.
//
// Auth: Azure uses OAuth2 client-credentials. We read
// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` from
// env and exchange at
// `login.microsoftonline.com/<tenant>/oauth2/v2.0/token` for an
// access token scoped to `https://vault.azure.net/.default`.

/// Azure AD `OAuth2` base URL.
#[cfg(feature = "kms-integration")]
const AZURE_OAUTH_BASE: &str = "https://login.microsoftonline.com";

/// Azure Key Vault `OAuth2` scope.
#[cfg(feature = "kms-integration")]
const AZURE_VAULT_SCOPE: &str = "https://vault.azure.net/.default";

/// Azure Key Vault Keys REST API version.
#[cfg(feature = "kms-integration")]
const AZURE_KEYVAULT_API_VERSION: &str = "7.4";

#[cfg(feature = "kms-integration")]
fn write_cloud_kms_key_azure(region: &str, current_alias: &str) -> Result<String, RotationError> {
    let _ = region; // accepted for API symmetry; region is implicit in the vault URL.

    let tenant = std::env::var("AZURE_TENANT_ID").map_err(|_| RotationError::WriteKey {
        reason: "cloud-kms-oracle/azure: AZURE_TENANT_ID env var not set",
    })?;
    let client_id = std::env::var("AZURE_CLIENT_ID").map_err(|_| RotationError::WriteKey {
        reason: "cloud-kms-oracle/azure: AZURE_CLIENT_ID env var not set",
    })?;
    let client_secret =
        std::env::var("AZURE_CLIENT_SECRET").map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/azure: AZURE_CLIENT_SECRET env var not set",
        })?;

    let key_resource = current_alias.to_owned();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/azure: failed to spin a tokio runtime for KMS rotation",
        })?;

    rt.block_on(async move {
        let access_token =
            azure_exchange_credentials_for_token(&tenant, &client_id, &client_secret).await?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| RotationError::WriteKey {
                reason: "cloud-kms-oracle/azure: failed to build HTTP client",
            })?;

        // Key Vault rotation primitive: POST to
        // `<vault>/keys/<name>/create?api-version=…`. Sending an
        // existing key name produces a new version of the key,
        // automatically promoted to the active version.
        let create_url = format!("{key_resource}/create?api-version={AZURE_KEYVAULT_API_VERSION}",);
        // P-256 (`P-256` curve) is the closest stable SECP-curve Key
        // Vault offers for ECDSA. SECP256K1 is preview-only in some
        // Azure regions; we use P-256 to match the durability of the
        // AWS path. The signer impl in `cloud_kms.rs` decodes
        // whichever curve the Key Vault returns at sign time.
        let create_body = serde_json::json!({
            "kty":     "EC",
            "crv":     "P-256",
            "key_ops": ["sign", "verify"],
            "attributes": {
                "enabled": true,
            },
            "tags": {
                "polaris": "labeler-signing-key-rotated",
            },
        });
        let create_resp = client
            .post(&create_url)
            .bearer_auth(&access_token)
            .header("Content-Type", "application/json")
            .body(create_body.to_string())
            .send()
            .await
            .map_err(|_| RotationError::WriteKey {
                reason: "cloud-kms-oracle/azure: createKey HTTP failed",
            })?;
        if !create_resp.status().is_success() {
            tracing::warn!(
                status = %create_resp.status(),
                "cloud-kms-oracle/azure: createKey returned non-2xx",
            );
            return Err(RotationError::WriteKey {
                reason: "cloud-kms-oracle/azure: createKey returned non-2xx",
            });
        }
        let body: serde_json::Value =
            create_resp
                .json()
                .await
                .map_err(|_| RotationError::WriteKey {
                    reason: "cloud-kms-oracle/azure: createKey response JSON decode failed",
                })?;
        // The new version's identifier is `body.key.kid`, of the
        // shape `<vault>/keys/<name>/<version-id>`. Return that
        // verbatim so the persisted alias can target the precise
        // version. Key Vault automatically routes plain
        // `<vault>/keys/<name>` calls to the latest version, but
        // capturing the explicit version-id makes rollbacks trivial.
        let kid = body
            .get("key")
            .and_then(|k| k.get("kid"))
            .and_then(|v| v.as_str())
            .ok_or(RotationError::WriteKey {
                reason: "cloud-kms-oracle/azure: createKey response missing `key.kid`",
            })?
            .to_owned();
        Ok(kid)
    })
}

#[cfg(not(feature = "kms-integration"))]
fn write_cloud_kms_key_azure(_region: &str, _current_alias: &str) -> Result<String, RotationError> {
    Err(RotationError::Unsupported {
        mode: "cloud-kms-oracle/azure (requires `kms-integration` cargo feature)",
    })
}

#[cfg(feature = "kms-integration")]
async fn azure_exchange_credentials_for_token(
    tenant: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, RotationError> {
    let token_url = format!("{AZURE_OAUTH_BASE}/{tenant}/oauth2/v2.0/token");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/azure: failed to build OAuth2 HTTP client",
        })?;
    let resp = client
        .post(&token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", AZURE_VAULT_SCOPE),
        ])
        .send()
        .await
        .map_err(|_| RotationError::WriteKey {
            reason: "cloud-kms-oracle/azure: OAuth2 token exchange HTTP failed",
        })?;
    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            "cloud-kms-oracle/azure: OAuth2 token exchange returned non-2xx",
        );
        return Err(RotationError::WriteKey {
            reason: "cloud-kms-oracle/azure: OAuth2 token exchange returned non-2xx",
        });
    }
    let body: serde_json::Value = resp.json().await.map_err(|_| RotationError::WriteKey {
        reason: "cloud-kms-oracle/azure: OAuth2 token-exchange JSON decode failed",
    })?;
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(RotationError::WriteKey {
            reason: "cloud-kms-oracle/azure: OAuth2 token-exchange response missing access_token",
        })
}

/// Atomically write arbitrary bytes to `path` with mode `0o600`.
///
/// Same atomic-rename strategy as [`write_key_atomic`]; the byte-
/// oriented variant exists for the sealed-blob write path which is
/// not UTF-8.
fn write_bytes_atomic(path: &std::path::Path, contents: &[u8]) -> Result<(), &'static str> {
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
    file.write_all(contents)
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

    // ── #64a/b — per-mode write-path tests ───────────────────────────

    #[test]
    fn rotation_custody_params_mode_matches_variant() {
        assert_eq!(
            RotationCustodyParams::FilePlain.mode(),
            CustodyMode::FilePlain
        );
        assert_eq!(
            RotationCustodyParams::PassphraseSealed {
                passphrase: "x".to_owned()
            }
            .mode(),
            CustodyMode::PassphraseSealed,
        );
        assert_eq!(
            RotationCustodyParams::OsKeychain {
                account: "a".to_owned()
            }
            .mode(),
            CustodyMode::OsKeychain,
        );
        assert_eq!(
            RotationCustodyParams::CloudKms {
                provider: crate::config::KmsProvider::Aws,
                region: "us-east-1".to_owned(),
                current_alias: "alias/polaris-labeler".to_owned(),
            }
            .mode(),
            CustodyMode::CloudKms,
        );
    }

    /// Passphrase-sealed rotation write path: seal a fresh K-256
    /// secret to a temp path, then drive
    /// `PassphraseSealedSigner::from_sealed_bytes_with_passphrase` over
    /// the resulting blob and confirm a sign+verify roundtrip against
    /// the original public key.
    ///
    /// The env-driven `from_path` entry point requires
    /// `POLARIS_SIGNING_PASSPHRASE`; we deliberately avoid touching
    /// the global env (the `#![deny(unsafe_code)]` crate attribute
    /// forbids `std::env::set_var` calls in this codebase). The
    /// in-process `from_sealed_bytes_with_passphrase` is the test-only
    /// twin of `from_path` and exercises the exact same AES-GCM /
    /// scrypt cycle, just sourcing the passphrase as a parameter.
    #[test]
    fn write_passphrase_sealed_key_roundtrip_sign_verify() {
        use crate::labeler::signer::SigningKey as _;
        use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Verifier as _};

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("k.sealed");

        let kp = K256Keypair::generate();
        let secret: [u8; 32] = kp.export_private_key().try_into().unwrap();
        let passphrase = "test-passphrase";

        // Write via the rotation helper.
        write_passphrase_sealed_key(&path, &secret, passphrase).unwrap();

        // The on-disk format is the v1 sealed blob: magic 0x01, 16-byte
        // salt, 12-byte nonce, ciphertext+tag. Total = 1+16+12+32+16 = 77.
        let blob = std::fs::read(&path).unwrap();
        assert_eq!(blob.len(), 77, "v1 sealed blob length stable");
        assert_eq!(blob[0], 0x01, "v1 sealed blob magic byte");

        // 0o600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "sealed write must land mode 0o600");
        }

        // Drive the in-process unseal entry point, then sign+verify.
        let signer =
            PassphraseSealedSigner::from_sealed_bytes_with_passphrase(&blob, passphrase).unwrap();
        let payload = b"polaris label payload";
        let sig = signer.sign(payload).unwrap();
        let verifier = K256Keypair::verifier_from_compressed(&kp.public_key_compressed()).unwrap();
        assert!(verifier.verify(payload, sig.as_bytes()).unwrap());
        assert_eq!(signer.public_key_did(), kp.did());
    }

    #[test]
    fn write_cloud_kms_key_rejects_gcp_and_azure_variants() {
        let err = write_cloud_kms_key(
            crate::config::KmsProvider::Gcp,
            "us-east-1",
            "alias/polaris-labeler",
        )
        .unwrap_err();
        match err {
            RotationError::Unsupported { mode } => {
                assert!(mode.contains("gcp"), "got {mode}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }

        let err = write_cloud_kms_key(
            crate::config::KmsProvider::Azure,
            "us-east-1",
            "alias/polaris-labeler",
        )
        .unwrap_err();
        match err {
            RotationError::Unsupported { mode } => {
                assert!(mode.contains("azure"), "got {mode}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// AWS-without-feature path: when the `kms-integration` Cargo
    /// feature is OFF, the rotation helper short-circuits with
    /// `Unsupported` naming the missing feature flag. Mirrors the
    /// convention in `signer::cloud_kms::tests`.
    #[cfg(not(feature = "kms-integration"))]
    #[test]
    fn write_cloud_kms_key_aws_without_feature_returns_unsupported() {
        let err = write_cloud_kms_key(
            crate::config::KmsProvider::Aws,
            "us-east-1",
            "alias/polaris-labeler",
        )
        .unwrap_err();
        match err {
            RotationError::Unsupported { mode } => {
                assert!(mode.contains("kms-integration"), "got {mode}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// AWS-with-feature integration test against localstack. Skipped
    /// (not failed) when `POLARIS_KMS_TEST_REGION` /
    /// `POLARIS_KMS_TEST_ALIAS` are unset — same gate convention as
    /// `signer::cloud_kms::aws::tests::aws_kms_roundtrip_against_localstack`.
    #[cfg(feature = "kms-integration")]
    #[test]
    fn write_cloud_kms_key_aws_alias_swap_against_localstack() {
        let Ok(region) = std::env::var("POLARIS_KMS_TEST_REGION") else {
            eprintln!("skipping: POLARIS_KMS_TEST_REGION unset");
            return;
        };
        let Ok(alias) = std::env::var("POLARIS_KMS_TEST_ALIAS") else {
            eprintln!("skipping: POLARIS_KMS_TEST_ALIAS unset");
            return;
        };
        let new_key_id =
            write_cloud_kms_key(crate::config::KmsProvider::Aws, &region, &alias).unwrap();
        assert!(
            !new_key_id.is_empty(),
            "AWS KMS CreateKey must return a non-empty key id"
        );
    }

    /// OS keychain round-trip. Ignored by default: the test mutates
    /// real OS credential-store state (would pollute the developer's
    /// keychain) and the keychain daemons (Secret Service, macOS
    /// Keychain, Windows Credential Manager) are not available in a
    /// stock CI sandbox. To exercise locally on macOS / Linux /
    /// Windows:
    ///
    /// ```bash
    /// cargo test -p polaris-backend labeler::rotation::tests::write_os_keychain -- --ignored
    /// ```
    ///
    /// On Linux additionally requires a running Secret Service daemon
    /// (`gnome-keyring-daemon` or `kwalletd`).
    #[ignore = "requires a real OS keychain daemon — see test docstring"]
    #[test]
    fn write_os_keychain_key_roundtrip() {
        use crate::labeler::signer::SigningKey as _;
        use proto_blue::crypto::{ExportableKeypair as _, K256Keypair};

        let account = format!("rotation-test-{}", Uuid::new_v4());
        let kp = K256Keypair::generate();
        let secret_hex = hex::encode(kp.export_private_key());

        write_os_keychain_key(&account, &secret_hex).unwrap();

        // Read back via the signer's entry point — both sides must
        // agree on the (service, account) pair and the hex encoding.
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let signer =
                crate::labeler::signer::os_keychain::OsKeychainSigner::from_account(&account)?;
            assert_eq!(signer.public_key_did(), kp.did());
            Ok(())
        })();

        // Tidy up the keychain entry, even if the test failed.
        if let Ok(entry) = keyring::Entry::new(
            crate::labeler::signer::os_keychain::KEYRING_SERVICE,
            &account,
        ) {
            let _ = entry.delete_credential();
        }
        result.unwrap();
    }

    #[test]
    fn new_rotation_rejects_mismatched_params_variant() {
        // Pure constructor-shape test: drive `new_rotation` with a
        // mode/params disagreement and confirm `Init` is returned
        // before any DB work. The variant check runs strictly before
        // the first query, so an unreachable lazy pool is fine — a
        // failure to short-circuit would surface as a `Db` error
        // (caught by the assertion's `other` branch).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
                .unwrap();
            RotationContext::new_rotation(
                pool,
                CustodyMode::PassphraseSealed,
                std::path::PathBuf::from("/tmp/nope"),
                RotationCustodyParams::FilePlain,
            )
            .await
            .unwrap_err()
        });
        match err {
            RotationError::Init { reason } => {
                assert!(reason.contains("does not match"), "got {reason}");
            }
            other => panic!("expected Init, got {other:?}"),
        }
    }
}
