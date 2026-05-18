//! Cross-test helpers for the `polaris-backend` integration suite.
//!
//! Exposes a small, deliberately-narrow surface so test binaries under
//! `polaris-backend/tests/` can share boot-time setup without duplicating
//! it across every file. The first entry point is
//! [`seed_placeholder_policies`], added for WB-2 (#224) so the
//! action-create handler's new `mod_policies` lookup finds the
//! pre-existing placeholder identifiers (`polaris.spam`,
//! `polaris.harassment`, …) the existing test suite cites.
//!
//! # Why a separate module, not a `tests/common/mod.rs`?
//!
//! Each Rust integration-test binary in `tests/` is a separate crate;
//! a `tests/common/mod.rs` would have to be re-`include!`-d per file.
//! Exposing the helpers on the library crate is simpler, keeps the
//! seed payload in one place, and lets the rest of the workspace
//! depend on the same constants.

use sqlx::PgPool;
use uuid::Uuid;

use crate::repo::mod_policies::{self, ModPolicyError, NewModPolicy};

/// The placeholder policy identifiers the WB-2 action API expects to
/// resolve via `mod_policies::current_by_identifier`. Mirrors the old
/// `KNOWN_POLICY_REFS` slice that lived in `api/policy.rs` so existing
/// tests citing these identifiers continue to pass against the new
/// lookup path. The production deploy seed (WB-5 / #227) will own the
/// canonical operator-curated set.
pub const PLACEHOLDER_POLICY_IDENTIFIERS: &[&str] = &[
    "polaris.harassment",
    "polaris.spam",
    "polaris.csam",
    "polaris.impersonation",
    "polaris.copyright",
];

/// Seed the placeholder policy set into `mod_policies`, idempotently.
///
/// Inserts one v1 row per identifier in [`PLACEHOLDER_POLICY_IDENTIFIERS`],
/// each authored by `created_by_moderator_id`. The caller supplies that
/// FK because moderators are seeded per-test (each integration test
/// builds its own moderator row); this function does not invent one.
///
/// Re-running is a no-op — identifiers already present at v1 short-circuit
/// without raising. The check is a SELECT before INSERT rather than an
/// `ON CONFLICT` because [`NewModPolicy`] does not expose
/// `effective_until` / `version` and we'd rather avoid forcing the repo
/// to grow an `insert_initial_idempotent` variant for one caller.
///
/// # Errors
///
/// Returns the underlying `sqlx::Error` if any individual insert fails
/// for a reason other than "already present at v1".
pub async fn seed_placeholder_policies(
    pool: &PgPool,
    created_by_moderator_id: Uuid,
) -> Result<(), sqlx::Error> {
    for identifier in PLACEHOLDER_POLICY_IDENTIFIERS {
        // Skip if a row already exists at v1 — keeps the helper
        // idempotent across re-seeds in long-lived test pools.
        let exists = sqlx::query!(
            r"SELECT 1 AS one FROM mod_policies WHERE identifier = $1 AND version = 1",
            *identifier,
        )
        .fetch_optional(pool)
        .await?
        .is_some();
        if exists {
            continue;
        }
        let mut tx = pool.begin().await?;
        mod_policies::insert_initial(
            &mut tx,
            NewModPolicy {
                identifier: (*identifier).to_owned(),
                name: format!("{identifier} placeholder"),
                description: format!("Test placeholder for {identifier}."),
                scope: "post".to_owned(),
                severity: "alert".to_owned(),
                // ≥ 64 chars so the DB CHECK on `mod_policies` is
                // satisfied. The test fixture content is meaningless;
                // production seeds come from WB-5.
                decision_criteria: format!(
                    "Apply {identifier} when the workbook test fixture is exercising the action-create code path."
                ),
                examples_positive: None,
                examples_negative: None,
                suggested_action_kinds: vec!["label".to_owned()],
                linked_label_value: None,
                exceptions: None,
                human_required_always: false,
                autonomy_mode: "manual".to_owned(),
                autonomous_action_kinds: vec![],
                autonomous_confidence_threshold: 0.95,
                assisted_confidence_threshold: 0.70,
                change_summary: None,
            },
            created_by_moderator_id,
        )
        .await
        .map_err(unwrap_mod_policy_err)?;
        tx.commit().await?;
    }
    Ok(())
}

/// Coerce a [`ModPolicyError`] into [`sqlx::Error`] so callers using the
/// short `Result<_, sqlx::Error>` signature can `?` through. Only the
/// `Database` variant carries an actual `sqlx::Error`; the typed
/// workbook variants (`UnknownIdentifier`, `RetiredPolicy`, …) cannot
/// arise from an `insert_initial` against a fresh identifier, so the
/// fall-through maps them through `Protocol` with the Display string.
fn unwrap_mod_policy_err(err: ModPolicyError) -> sqlx::Error {
    match err {
        ModPolicyError::Database(inner) => inner,
        other => sqlx::Error::Protocol(other.to_string()),
    }
}
