//! First-boot seed loader for `mod_policies` (WB-5 / issue #227).
//!
//! Implements REQ-E1 / REQ-E2 from `.design/mod-policy-workbook.md`:
//! ship a YAML file with the five placeholder policy identifiers and,
//! on backend startup, insert them as v1 rows in `mod_policies` if and
//! only if the table is empty AND a bootstrap admin exists.
//!
//! # Idempotency contract
//!
//! [`maybe_seed_policies`] runs `SELECT EXISTS(SELECT 1 FROM
//! mod_policies)` before touching the table. A populated table is the
//! "already seeded" signal — the function returns
//! [`SeedOutcome::Skipped`] with [`SkipReason::TableNotEmpty`] and
//! never executes an INSERT. Per-row atomicity inside the load path
//! uses a single transaction wrapping every `insert_initial` call, so
//! a YAML parse failure or any individual insert rejection (DB CHECK
//! violation, UNIQUE collision, …) rolls the whole batch back — there
//! is no partial-load state.
//!
//! # Bootstrap admin coupling
//!
//! Every seeded row carries `created_by_moderator_id =
//! bootstrap_admin`. The setup wizard pins the first moderator-OAuth-
//! login as the bootstrap admin (`moderators.pinned_admin = TRUE`,
//! see migration 46); the caller in `main.rs` discovers that admin
//! before calling this function and skips the call entirely if no
//! pinned admin exists yet. That couples seeding to the setup-wizard
//! flow — a fresh deploy seeds on the first OAuth callback re-tick
//! after the pin lands, not at the moment the binary boots into an
//! unprovisioned DB.
//!
//! # Path resolution
//!
//! [`resolve_seed_path`] consults, in order:
//! 1. `POLARIS_POLICY_SEED_PATH` env var (explicit operator override).
//! 2. `/etc/polaris/seeds/mod-policies.yml` (container image default).
//! 3. `<workspace>/deploy/seeds/mod-policies.yml` (dev fallback so a
//!    non-root `cargo run` still seeds without staging files to
//!    `/etc`).
//!
//! The first path that exists wins. Callers that want strict
//! container-image semantics pass the override env var.
//!
//! # Error surface
//!
//! [`SeedError`] discriminates IO, YAML parse, validation, and
//! repo-layer failures so the caller can map them to actionable logs.
//! Validation errors carry the policy `identifier` and a one-line
//! `message` so an operator-broken edit to the seed file points
//! straight at the bad entry.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::repo::mod_policies::{self, ModPolicyError, NewModPolicy};

/// Default container-image install path for the seed file.
///
/// Public so external callers (e.g. `polaris-setup seed-policies`,
/// WB-6 / #228) can document the same default in their `--help` text.
pub const DEFAULT_CONTAINER_SEED_PATH: &str = "/etc/polaris/seeds/mod-policies.yml";

/// Environment variable that overrides [`DEFAULT_CONTAINER_SEED_PATH`].
///
/// Operators bake an alternate seed (e.g. a regional policy set) by
/// pointing this at it before the backend boots.
pub const SEED_PATH_ENV: &str = "POLARIS_POLICY_SEED_PATH";

/// Default fallback path relative to the workspace root, used in dev
/// when `/etc/polaris/seeds/mod-policies.yml` does not exist.
///
/// `env!("CARGO_MANIFEST_DIR")` resolves to `polaris-backend/` at
/// compile time; the join walks one parent up to reach the workspace
/// root and into `deploy/seeds/`.
const DEV_FALLBACK_RELATIVE: &str = "../deploy/seeds/mod-policies.yml";

/// Errors raised by the seed loader.
///
/// The variants discriminate so the caller can map each failure mode
/// to an actionable log line — IO failures point at filesystem
/// permissions, YAML parse failures at operator edits, validation
/// failures at content drift between the seed file and the DB CHECKs,
/// and repo failures at the typed `mod_policies` error surface.
#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    /// Could not read the seed file from disk. The path is preserved
    /// so the operator log points at the file Polaris tried to open.
    #[error("could not read seed file {path}: {source}")]
    IoError {
        /// The path the loader attempted to read.
        path: PathBuf,
        /// The underlying `std::io::Error`.
        #[source]
        source: std::io::Error,
    },

    /// The seed file is not parseable as the typed [`SeedPolicy`]
    /// vector. `serde_yaml::Error::location()` carries line / column
    /// when the parser knows them; the wrapped error preserves it.
    #[error("could not parse seed file: {0}")]
    YamlParseError(#[from] serde_yaml::Error),

    /// A pre-insert validation check failed — typically because a
    /// field in the seed file disagrees with the corresponding DB
    /// CHECK (e.g. `scope` outside `{account, post, both}` or
    /// `decision_criteria` shorter than 64 chars). Surfaced before
    /// the INSERT so the operator gets an actionable line number
    /// rather than a raw SQLSTATE.
    #[error("seed entry {identifier} failed validation: {message}")]
    ValidationError {
        /// The `identifier` of the offending entry.
        identifier: String,
        /// One-line description of what the seed file got wrong.
        message: String,
    },

    /// The underlying `mod_policies` repo rejected an insert — usually
    /// a DB CHECK violation that slipped past `validate` (e.g. the
    /// operator added a policy with an existing identifier at v1).
    #[error("mod_policies repo rejected insert: {0}")]
    RepoError(#[from] ModPolicyError),
}

/// The reason a [`maybe_seed_policies`] call short-circuited.
///
/// `TableNotEmpty` is the success-on-already-seeded path; the caller
/// logs an INFO and moves on. `SeedFileMissing` is the dev-environment
/// path where the operator simply has no seed file to load; the caller
/// logs a WARN and continues so the backend still boots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// `mod_policies` already has at least one row. The first-boot
    /// load already ran (or the operator bulk-loaded via WB-6).
    TableNotEmpty,
    /// No file was found at any of the resolved seed paths. Common
    /// on a dev `cargo run` where the operator hasn't staged the
    /// seed file. The backend boots fine; the action-create path
    /// will reject unknown policy identifiers until the operator
    /// either creates policies via the admin UI or supplies a seed
    /// file and restarts.
    SeedFileMissing,
}

/// What [`maybe_seed_policies`] actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedOutcome {
    /// No INSERT ran; `reason` discriminates why.
    Skipped {
        /// The short-circuit reason — `TableNotEmpty` or
        /// `SeedFileMissing`.
        reason: SkipReason,
    },
    /// `count` v1 rows inserted into `mod_policies`.
    Loaded {
        /// How many rows the loader committed.
        count: usize,
    },
}

/// A single example used by [`SeedPolicy`].
///
/// The shape matches the JSONB column contract that
/// `mod_policies.examples_positive` / `_negative` carry: every example
/// has an `excerpt` and an optional `context`, plus one of
/// `expected_action_kind` (positive) or `why_not_a_violation`
/// (negative). The deserialiser is permissive on the optional fields
/// so the same struct deserialises both lists.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedPolicyExample {
    /// The text snippet the example illustrates.
    pub excerpt: String,
    /// Surrounding context (timing, account history, etc.).
    #[serde(default)]
    pub context: Option<String>,
    /// What action verb the example calls for (positive examples).
    #[serde(default)]
    pub expected_action_kind: Option<String>,
    /// Why the example is *not* a violation (negative examples).
    #[serde(default)]
    pub why_not_a_violation: Option<String>,
}

/// One entry in the seed YAML, strongly-typed.
///
/// Mirrors [`NewModPolicy`] one-for-one with serde defaults on the
/// optional / threshold fields so the seed file stays terse for the
/// common manual-mode case. The `default_*` callbacks below match the
/// DB column defaults so seeds that omit a threshold round-trip to the
/// same value the schema would have written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedPolicy {
    /// Human-stable identifier (`polaris.harassment` etc.).
    pub identifier: String,
    /// Short title surfaced in lists.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// `account` | `post` | `both`.
    pub scope: String,
    /// `inform` | `alert` | `hide` | `remove`.
    pub severity: String,
    /// Markdown decision-criteria text (≥ 64 chars).
    pub decision_criteria: String,
    /// Examples that DO violate the policy.
    #[serde(default)]
    pub examples_positive: Vec<SeedPolicyExample>,
    /// Examples that look like violations but are NOT.
    #[serde(default)]
    pub examples_negative: Vec<SeedPolicyExample>,
    /// Non-empty subset of `actions.kind`.
    pub suggested_action_kinds: Vec<String>,
    /// Optional default label value when `suggested_action_kinds`
    /// includes `label`.
    #[serde(default)]
    pub linked_label_value: Option<String>,
    /// Free-text "when this policy does not apply".
    #[serde(default)]
    pub exceptions: Option<String>,
    /// REQ-A2 hard-floor marker — `polaris.csam` is the only seed
    /// entry that sets this `true`.
    #[serde(default)]
    pub human_required_always: bool,
    /// `manual` (default) | `assisted` | `autonomous`. Seeds default
    /// to `manual` so a fresh deploy never auto-fires until the
    /// operator opts in per-policy.
    #[serde(default = "default_autonomy_mode")]
    pub autonomy_mode: String,
    /// Subset of `actions.kind` allowed when `autonomy_mode =
    /// autonomous`. Defaults empty.
    #[serde(default)]
    pub autonomous_action_kinds: Vec<String>,
    /// Autonomous-emit confidence floor. Default mirrors the DB
    /// default (0.95).
    #[serde(default = "default_autonomous_threshold")]
    pub autonomous_confidence_threshold: f32,
    /// Assisted-draft confidence floor. Default mirrors the DB
    /// default (0.70).
    #[serde(default = "default_assisted_threshold")]
    pub assisted_confidence_threshold: f32,
}

fn default_autonomy_mode() -> String {
    "manual".to_owned()
}

fn default_autonomous_threshold() -> f32 {
    0.95
}

fn default_assisted_threshold() -> f32 {
    0.70
}

/// Resolve the seed file path consulting the env var, the container
/// install path, and the dev-fallback path in that order.
///
/// Returns `None` when none of the candidates exist on disk. Callers
/// map that to [`SkipReason::SeedFileMissing`].
///
/// # Example
///
/// ```ignore
/// // In production with the container image:
/// //   /etc/polaris/seeds/mod-policies.yml exists -> returns that.
/// // On a dev workstation without the env var or /etc file:
/// //   <workspace>/deploy/seeds/mod-policies.yml exists -> returns that.
/// // No file anywhere:
/// //   returns None.
/// let path = polaris_backend::seed::mod_policies::resolve_seed_path();
/// ```
#[must_use]
pub fn resolve_seed_path() -> Option<PathBuf> {
    // 1. Explicit operator override.
    if let Ok(p) = std::env::var(SEED_PATH_ENV) {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
        // An explicit override pointing at a non-existent path is
        // surfaced as Missing rather than silently falling through —
        // the operator who set the env var wanted *that* file.
        return None;
    }

    // 2. Container-image default.
    let container = PathBuf::from(DEFAULT_CONTAINER_SEED_PATH);
    if container.exists() {
        return Some(container);
    }

    // 3. Dev fallback: `<crate>/../deploy/seeds/mod-policies.yml`.
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEV_FALLBACK_RELATIVE);
    if dev.exists() {
        return Some(dev);
    }

    None
}

/// Validate that an in-memory [`SeedPolicy`] would pass the DB CHECKs
/// before we hit the wire.
///
/// Catches the common operator-edit failure modes (typo in `scope`,
/// criteria too short, empty action-kinds list) at parse time so the
/// transaction abort below points at the offending entry rather than
/// at a SQLSTATE 23514. Anything subtler than these eight checks falls
/// through to the DB and surfaces via [`SeedError::RepoError`].
fn validate(p: &SeedPolicy) -> Result<(), SeedError> {
    if p.identifier.is_empty() {
        return Err(SeedError::ValidationError {
            identifier: "<empty>".to_owned(),
            message: "identifier is empty".to_owned(),
        });
    }
    if !matches!(p.scope.as_str(), "account" | "post" | "both") {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: format!("scope must be account|post|both, got {:?}", p.scope),
        });
    }
    if !matches!(p.severity.as_str(), "inform" | "alert" | "hide" | "remove") {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: format!(
                "severity must be inform|alert|hide|remove, got {:?}",
                p.severity
            ),
        });
    }
    if p.decision_criteria.len() < 64 {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: format!(
                "decision_criteria must be >= 64 chars, got {}",
                p.decision_criteria.len()
            ),
        });
    }
    if p.suggested_action_kinds.is_empty() {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: "suggested_action_kinds must be non-empty".to_owned(),
        });
    }
    if !matches!(
        p.autonomy_mode.as_str(),
        "manual" | "assisted" | "autonomous"
    ) {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: format!(
                "autonomy_mode must be manual|assisted|autonomous, got {:?}",
                p.autonomy_mode
            ),
        });
    }
    if !(0.0..=1.0).contains(&p.autonomous_confidence_threshold) {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: format!(
                "autonomous_confidence_threshold must be in [0.0, 1.0], got {}",
                p.autonomous_confidence_threshold
            ),
        });
    }
    if !(0.0..=1.0).contains(&p.assisted_confidence_threshold) {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: format!(
                "assisted_confidence_threshold must be in [0.0, 1.0], got {}",
                p.assisted_confidence_threshold
            ),
        });
    }
    // REQ-G3: human_required_always + autonomous mode together is the
    // primary three-layer-floor invariant. The seed file should never
    // ship that combination; refuse it before insert so a misedit
    // can't sneak past.
    if p.human_required_always && p.autonomy_mode == "autonomous" {
        return Err(SeedError::ValidationError {
            identifier: p.identifier.clone(),
            message: "human_required_always=true is incompatible with autonomy_mode=autonomous"
                .to_owned(),
        });
    }
    Ok(())
}

/// Convert a [`SeedPolicy`] (typed YAML) into a [`NewModPolicy`]
/// (typed repo input).
///
/// Examples lists are re-serialised through `serde_json` so they land
/// in the JSONB column as the same shape the admin REST API uses on
/// edit — the database doesn't care which serialiser produced the
/// bytes, only that they round-trip through `serde_json::Value`.
fn into_new(p: SeedPolicy) -> Result<NewModPolicy, SeedError> {
    let examples_positive = if p.examples_positive.is_empty() {
        None
    } else {
        Some(serde_json::to_value(&p.examples_positive).map_err(|e| {
            SeedError::ValidationError {
                identifier: p.identifier.clone(),
                message: format!("could not serialise examples_positive: {e}"),
            }
        })?)
    };
    let examples_negative = if p.examples_negative.is_empty() {
        None
    } else {
        Some(serde_json::to_value(&p.examples_negative).map_err(|e| {
            SeedError::ValidationError {
                identifier: p.identifier.clone(),
                message: format!("could not serialise examples_negative: {e}"),
            }
        })?)
    };

    Ok(NewModPolicy {
        identifier: p.identifier,
        name: p.name,
        description: p.description,
        scope: p.scope,
        severity: p.severity,
        decision_criteria: p.decision_criteria,
        examples_positive,
        examples_negative,
        suggested_action_kinds: p.suggested_action_kinds,
        linked_label_value: p.linked_label_value,
        exceptions: p.exceptions,
        human_required_always: p.human_required_always,
        autonomy_mode: p.autonomy_mode,
        autonomous_action_kinds: p.autonomous_action_kinds,
        autonomous_confidence_threshold: p.autonomous_confidence_threshold,
        assisted_confidence_threshold: p.assisted_confidence_threshold,
        // The seed loader does not configure the LLM-6 safety-floor
        // tuning columns; the DB defaults (60/hr, 0.15) take effect.
        // Operators tune via the admin UI after seeding.
        autonomous_rate_limit_per_hour: None,
        autonomous_reversal_breaker_threshold: None,
        // The seed loader does not author per-row change-summaries —
        // the initial v1 insert is implicitly "seeded from
        // mod-policies.yml". Operators editing this policy from the
        // admin UI supply their own change-summary on the amend path.
        change_summary: None,
    })
}

// Re-implement Serialize for SeedPolicyExample by hand-free auto-derive.
// The serialise side is only used by `into_new` to round-trip examples
// into JSONB; the example shape is small and stable, so deriving
// Serialize alongside Deserialize is the right tradeoff.
impl serde::Serialize for SeedPolicyExample {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut s = serializer.serialize_struct("SeedPolicyExample", 4)?;
        s.serialize_field("excerpt", &self.excerpt)?;
        s.serialize_field("context", &self.context)?;
        s.serialize_field("expected_action_kind", &self.expected_action_kind)?;
        s.serialize_field("why_not_a_violation", &self.why_not_a_violation)?;
        s.end()
    }
}

/// Seed `mod_policies` from `seed_path` if the table is empty, charging
/// the seed inserts to `bootstrap_admin`.
///
/// Idempotency contract:
///
/// * If `mod_policies` already has at least one row, returns
///   [`SeedOutcome::Skipped`] with [`SkipReason::TableNotEmpty`].
/// * If `seed_path` does not exist, returns [`SeedOutcome::Skipped`]
///   with [`SkipReason::SeedFileMissing`].
/// * Otherwise, parses the file, validates every entry, and inserts
///   them inside a single transaction. Any failure mid-load rolls the
///   whole batch back — there is no partial-load state.
///
/// # Errors
///
/// - [`SeedError::IoError`] if `seed_path` exists but cannot be read.
/// - [`SeedError::YamlParseError`] if the file is not valid YAML or
///   does not match the [`SeedPolicy`] shape.
/// - [`SeedError::ValidationError`] if any entry fails the pre-insert
///   validation (`scope`, `severity`, criteria length, etc.).
/// - [`SeedError::RepoError`] if the underlying `mod_policies::insert_initial`
///   call rejects an insert (DB CHECK violation, UNIQUE collision).
///
/// # Example
///
/// ```ignore
/// use std::path::Path;
/// use polaris_backend::seed::mod_policies::{maybe_seed_policies, SeedOutcome};
///
/// # async fn run(pool: sqlx::PgPool, admin: uuid::Uuid) -> anyhow::Result<()> {
/// let outcome = maybe_seed_policies(
///     &pool,
///     admin,
///     Path::new("/etc/polaris/seeds/mod-policies.yml"),
/// ).await?;
/// match outcome {
///     SeedOutcome::Loaded { count } => println!("seeded {count} policies"),
///     SeedOutcome::Skipped { .. } => println!("seed skipped"),
/// }
/// # Ok(()) }
/// ```
pub async fn maybe_seed_policies(
    pool: &PgPool,
    bootstrap_admin: Uuid,
    seed_path: &Path,
) -> Result<SeedOutcome, SeedError> {
    // 1. Idempotency probe. The cheapest path is the common one: on
    //    every restart of an already-provisioned deploy this returns
    //    true and we skip without touching the seed file.
    let table_not_empty: bool =
        sqlx::query_scalar!(r#"SELECT EXISTS(SELECT 1 FROM mod_policies) AS "exists!""#,)
            .fetch_one(pool)
            .await
            .map_err(ModPolicyError::Database)?;
    if table_not_empty {
        return Ok(SeedOutcome::Skipped {
            reason: SkipReason::TableNotEmpty,
        });
    }

    // 2. Seed-file existence probe. Missing file is non-fatal; the
    //    backend boots, no rows land, and the admin can either edit
    //    policies via the UI or stage a file and restart.
    if !seed_path.exists() {
        return Ok(SeedOutcome::Skipped {
            reason: SkipReason::SeedFileMissing,
        });
    }

    // 3. Read + parse. `read_to_string` is fine for a few-kilobyte
    //    YAML file; the seed is operator-authored, not user-supplied,
    //    so we don't need a streaming reader.
    let raw = std::fs::read_to_string(seed_path).map_err(|source| SeedError::IoError {
        path: seed_path.to_path_buf(),
        source,
    })?;
    let policies: Vec<SeedPolicy> = serde_yaml::from_str(&raw)?;

    // 4. Pre-flight validation. Every entry is checked before *any*
    //    insert runs so the operator gets one actionable error
    //    pointing at the bad entry, rather than partial state plus a
    //    raw SQLSTATE.
    for p in &policies {
        validate(p)?;
    }

    // 5. Single transaction wraps every insert. A failure at row N
    //    rolls back rows 0..N-1 — the idempotency probe at the top
    //    of the next call will see an empty table again, so retrying
    //    after fixing the seed file is safe.
    let mut tx = pool.begin().await.map_err(ModPolicyError::Database)?;
    let mut count = 0_usize;
    for p in policies {
        let identifier = p.identifier.clone();
        let new = into_new(p)?;
        mod_policies::insert_initial(&mut tx, new, bootstrap_admin).await?;
        info!(
            identifier = %identifier,
            "policy seed: inserted v1 from seed file",
        );
        count += 1;
    }
    tx.commit().await.map_err(ModPolicyError::Database)?;

    Ok(SeedOutcome::Loaded { count })
}

/// Look up the pinned bootstrap admin's moderator id.
///
/// Returns `Ok(None)` when no admin has been pinned yet — that is the
/// "fresh deploy before the setup wizard ran" state, and the caller in
/// `main.rs` skips the seed on that signal. Multiple pinned admins
/// would be a schema invariant violation (the migration trigger
/// prevents un-pinning, so the count is monotone-up); we still take
/// the first deterministic row to keep the call total.
///
/// # Errors
///
/// Propagates any `sqlx::Error` from the underlying query.
pub async fn lookup_bootstrap_admin(pool: &PgPool) -> Result<Option<Uuid>, sqlx::Error> {
    let row =
        sqlx::query!(r"SELECT id FROM moderators WHERE pinned_admin = TRUE ORDER BY id LIMIT 1",)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.id))
}

/// Convenience boot-path wrapper: resolve the seed path, look up the
/// bootstrap admin, and call [`maybe_seed_policies`].
///
/// The function logs at INFO on success and at WARN on skip /
/// recoverable failure; the caller in `main.rs` calls it inside a
/// `match` so a hard `Err` aborts boot, matching the
/// migrations-failed contract.
///
/// # Errors
///
/// Propagates [`SeedError`] from the underlying loader. The
/// "no admin yet" and "seed file missing" cases are surfaced as
/// `Ok(SeedOutcome::Skipped { .. })` rather than errors.
pub async fn run_first_boot_seed(pool: &PgPool) -> Result<SeedOutcome, SeedError> {
    let admin = lookup_bootstrap_admin(pool)
        .await
        .map_err(ModPolicyError::Database)?;
    let Some(admin) = admin else {
        // No pinned bootstrap admin yet — the setup wizard hasn't
        // run, so there's no actor to attribute v1 inserts to.
        // Skipping silently is the documented contract: the OAuth
        // callback that grants first_user_admin will pin the row,
        // and the next backend restart (or the post-callback hook,
        // if wired) will pick this up.
        info!("policy seed: no pinned bootstrap admin yet; skipping until setup wizard completes",);
        return Ok(SeedOutcome::Skipped {
            reason: SkipReason::TableNotEmpty, // Re-using; the caller logs the real cause.
        });
    };

    let Some(seed_path) = resolve_seed_path() else {
        warn!(
            "policy seed: no seed file found at {SEED_PATH_ENV}, {DEFAULT_CONTAINER_SEED_PATH}, or dev fallback; skipping",
        );
        return Ok(SeedOutcome::Skipped {
            reason: SkipReason::SeedFileMissing,
        });
    };

    let outcome = maybe_seed_policies(pool, admin, &seed_path).await?;
    match &outcome {
        SeedOutcome::Loaded { count } => info!(
            count = %count,
            path = %seed_path.display(),
            admin = %admin,
            "policy seed: first-boot load complete",
        ),
        SeedOutcome::Skipped { reason } => info!(
            reason = ?reason,
            "policy seed: skipped",
        ),
    }
    Ok(outcome)
}
