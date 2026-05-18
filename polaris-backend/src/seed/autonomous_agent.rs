//! Autonomous-agent moderator seed (issue #246).
//!
//! The LLM dispatcher's autonomous-emit path writes every action with
//! `actor_kind = 'autonomous_agent'` and an `actions.moderator_id` FK
//! that points at a real row in `moderators`. The dispatcher itself
//! takes that id as a constructor argument so tests can supply a
//! freshly-seeded UUID per case; production wiring needs a single
//! stable id that survives restarts and migrations.
//!
//! This module owns the boot-time invariant: "there is always exactly
//! one `moderators` row with `external_id = polaris:autonomous-agent`,
//! `auth_backend = 'oidc'`, no roles assigned (the FK is the only
//! load-bearing property)". `ensure_autonomous_agent_moderator`
//! inserts the row idempotently and returns the wrapped
//! [`polaris_types::ModeratorId`] — the canonical shared id type the
//! dispatcher consumes (distinct from `crate::auth::ModeratorId`, the
//! HTTP-auth identifier).
//!
//! Why `auth_backend = 'oidc'` rather than a new sentinel value: the
//! `moderators.auth_backend` CHECK constraint accepts only `'oidc'`
//! and `'atproto'`. Widening the CHECK to introduce a third value
//! ('autonomous') would be a workspace-wide migration plus an audit
//! to every code path that joins on `auth_backend`. Re-using `oidc`
//! with a `polaris:`-prefixed `external_id` is the minimum-blast-
//! radius alternative — the prefix is reserved by convention; no
//! real OIDC subject can collide with it.
//!
//! Why no role rows: the autonomous-agent moderator must never be
//! able to sign in. The role table is empty for this row; the auth
//! middleware's role check would refuse a session even if one could
//! somehow be minted, and no `INSERT INTO sessions ... moderator_id
//! = <autonomous-agent>` exists anywhere in the codebase.

use polaris_types::ModeratorId;
use sqlx::PgPool;

/// `external_id` value used for the autonomous-agent row. Reserved
/// prefix `polaris:` cannot collide with a real OIDC subject. Stable
/// across deployments so an audit reader can correlate autonomous
/// actions back to "the autonomous agent" by joining on `actions.
/// moderator_id = (SELECT id FROM moderators WHERE external_id =
/// 'polaris:autonomous-agent')`.
const AUTONOMOUS_AGENT_EXTERNAL_ID: &str = "polaris:autonomous-agent";

/// Auth backend used for the autonomous-agent row. Constrained by the
/// `moderators.auth_backend` CHECK to one of `'oidc'` / `'atproto'`;
/// `'oidc'` is the value that does not conflict with the `atproto`
/// OAuth path's `moderators.external_id = '<did>'` shape.
const AUTONOMOUS_AGENT_AUTH_BACKEND: &str = "oidc";

/// Display name surfaced to admins reading the moderators list or the
/// audit page. Constant so the row's appearance does not drift across
/// reboots.
const AUTONOMOUS_AGENT_DISPLAY_NAME: &str = "Polaris autonomous agent";

/// Ensure the autonomous-agent moderator row exists, returning its id.
///
/// Idempotent — running on every boot is the intended pattern. The
/// `ON CONFLICT (auth_backend, external_id) DO UPDATE SET
/// display_name = EXCLUDED.display_name` arm refreshes the display
/// name if a future release renames the agent, without rewriting the
/// id (which is what every `actions.moderator_id` already references).
///
/// # Errors
///
/// Returns the underlying [`sqlx::Error`] on a DB failure. Boot is
/// the only caller; an error here aborts startup the same way a
/// migration failure does.
pub async fn ensure_autonomous_agent_moderator(pool: &PgPool) -> Result<ModeratorId, sqlx::Error> {
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend, display_name)
          VALUES ($1, $2, $3)
          ON CONFLICT (auth_backend, external_id) DO UPDATE
            SET display_name = EXCLUDED.display_name
          RETURNING id",
        AUTONOMOUS_AGENT_EXTERNAL_ID,
        AUTONOMOUS_AGENT_AUTH_BACKEND,
        AUTONOMOUS_AGENT_DISPLAY_NAME,
    )
    .fetch_one(pool)
    .await?;
    Ok(ModeratorId(row.id))
}
