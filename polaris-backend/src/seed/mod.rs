//! First-boot seed loaders (WB-5 / issue #227).
//!
//! The submodules under this namespace populate operator-curated tables
//! from versioned YAML files shipped in `deploy/seeds/`. Each loader is
//! idempotent: a non-empty target table short-circuits the load before
//! any insert runs, so re-running on an upgraded deployment is a no-op
//! (REQ-E2).
//!
//! The seed step is called from `main.rs` *after* migrations succeed
//! AND a bootstrap admin has been pinned (`moderators.pinned_admin =
//! TRUE`). The bootstrap admin couples policy seeding to the existing
//! setup-wizard flow — `created_by_moderator_id` on every seeded row
//! points at that operator so every workbook entry carries an actor
//! and the audit trail is complete from the first row.
//!
//! See `.design/mod-policy-workbook.md` REQ-E1 / REQ-E2 / AC-6.

pub mod autonomous_agent;
pub mod mod_policies;
