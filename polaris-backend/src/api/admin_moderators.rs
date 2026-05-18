//! Admin-only moderator-management API (issue #214).
//!
//! Operators manage the login allow-list (which DIDs may complete an
//! OAuth dance) and the per-DID role assignment (admin / senior /
//! moderator / triage) through this surface. Every endpoint requires
//! `Role::Admin`; the auth middleware (`crate::middleware::auth`)
//! attaches the `ModeratorAuthCtx` extension on every authenticated
//! request, and [`require_admin`] consumes it.
//!
//! # Endpoints
//!
//! - `GET /api/admin/moderators` — list every moderator with their
//!   role set, pinned flag, and last-login timestamp. Sorted by
//!   handle / DID for a stable UI ordering.
//! - `POST /api/admin/moderators` — resolve a handle → DID, upsert
//!   the moderator row, and grant a single role. Idempotent on
//!   `(handle, role)` — re-POSTing the same pair is a no-op.
//! - `PATCH /api/admin/moderators/:did/roles` — toggle a single role
//!   on the moderator. Refuses to remove `admin` from the last
//!   admin (the deployment must always have at least one admin) or
//!   from a pinned admin (the bootstrap operator is hard-pinned).
//! - `DELETE /api/admin/moderators/:did` — refuses if the target is
//!   pinned; otherwise deletes the row (FK cascade clears
//!   `moderator_roles`).
//!
//! # Audit trail
//!
//! Every mutating endpoint appends an `audit_log` row inside the
//! same transaction as the write so a failed audit append rolls the
//! write back. The kinds used:
//!
//! - `moderator_added` — POST (new allow-list entry).
//! - `moderator_role_changed` — PATCH (grant or revoke).
//! - `moderator_removed` — DELETE (full removal).
//!
//! Each payload carries the actor (the calling admin's moderator id),
//! the target DID, and the role that changed.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{AnyModeratorAuth, ModeratorAuthCtx, Role};

/// Wire shape for one moderator row.
///
/// The DID is rendered as a bare string (not the typed `polaris_types::Did`
/// newtype) because the frontend deserialises into a TypeScript string
/// at the boundary anyway, and the typed serde envelope is `transparent`
/// — the wire bytes are identical either way.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeratorDto {
    /// The moderator's external identifier — DID for atproto, OIDC
    /// `sub` for OIDC. Stored in `moderators.external_id`.
    pub did: String,
    /// Auth backend the row was created under (`"atproto"` or
    /// `"oidc"`). Surfaced so the frontend can render a per-backend
    /// icon without inferring it from the DID shape.
    pub auth_backend: String,
    /// Display name, if known.
    pub display_name: Option<String>,
    /// Role set granted to this moderator. Snake-case strings
    /// matching `Role::as_db_str`. Sorted alphabetically for a
    /// stable UI rendering.
    pub roles: Vec<String>,
    /// `true` if this moderator is the hard-pinned bootstrap admin
    /// (issue #214). Pinned admins cannot be deleted via this API
    /// and cannot lose their `admin` role.
    pub pinned_admin: bool,
    /// Last successful login timestamp, if any.
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Request body for `POST /api/admin/moderators`.
#[derive(Debug, Clone, Deserialize)]
pub struct AddModeratorRequest {
    /// The moderator's ATProto handle (e.g. `alice.example.com`).
    /// The handler resolves it to a DID through the shared
    /// [`proto_blue::identity::IdResolver`] — same code path the
    /// login flow uses, so allow-list grants reach the same DID a
    /// future OAuth dance would.
    pub handle: String,
    /// Role to grant. One of `admin` / `senior_moderator` /
    /// `moderator` / `triage`. (`read_only` is omitted from the
    /// admin-facing API — the role still exists in the DB schema
    /// for historical reasons but is not selectable from the wire.)
    pub role: String,
}

/// Request body for `PATCH /api/admin/moderators/:did/roles`.
#[derive(Debug, Clone, Deserialize)]
pub struct PatchRolesRequest {
    /// Role to toggle.
    pub role: String,
    /// `true` to grant the role, `false` to revoke it.
    pub grant: bool,
}

/// Parse a wire role string into a typed [`Role`].
///
/// The admin surface restricts to the four operator-relevant tiers;
/// `read_only` is intentionally rejected here to keep the wire-facing
/// vocabulary small. A future expansion that wants to expose
/// read-only would extend this match.
fn parse_role(value: &str) -> Result<Role, ApiError> {
    match value {
        "admin" => Ok(Role::Admin),
        "senior_moderator" => Ok(Role::SeniorModerator),
        "moderator" => Ok(Role::Moderator),
        "triage" => Ok(Role::Triage),
        _ => Err(ApiError::BadRequest(
            "role must be one of: admin, senior_moderator, moderator, triage",
        )),
    }
}

/// Verify the caller is `Role::Admin`. Mirrors the shape of
/// `crate::api::setup::require_admin`; lives in this module so the
/// admin-moderators surface is self-contained.
fn require_admin(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Fetch every moderator row + their roles, ordered by `external_id`.
///
/// One query for moderators + one query for the role-grants joined
/// by moderator id keeps the wire build a single pass: the handler
/// stitches the two result sets in memory rather than running a
/// per-moderator `SELECT roles` query.
async fn fetch_all_moderators(pool: &PgPool) -> Result<Vec<ModeratorDto>, ApiError> {
    let rows = sqlx::query!(
        r"SELECT m.id            AS id,
                 m.external_id   AS external_id,
                 m.auth_backend  AS auth_backend,
                 m.display_name  AS display_name,
                 m.pinned_admin  AS pinned_admin,
                 m.last_login_at AS last_login_at
          FROM moderators m
          ORDER BY m.external_id ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let role_rows = sqlx::query!(
        r"SELECT moderator_id, role
          FROM moderator_roles
          ORDER BY role ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let roles: Vec<String> = role_rows
            .iter()
            .filter(|r| r.moderator_id == row.id)
            .map(|r| r.role.clone())
            .collect();
        out.push(ModeratorDto {
            did: row.external_id,
            auth_backend: row.auth_backend,
            display_name: row.display_name,
            roles,
            pinned_admin: row.pinned_admin,
            last_login_at: row.last_login_at,
        });
    }
    Ok(out)
}

/// Look up a single moderator row by DID. Returns `None` when no row
/// exists; callers translate that into the appropriate API error.
async fn fetch_moderator_by_did(
    pool: &PgPool,
    did: &str,
) -> Result<Option<ModeratorDto>, ApiError> {
    let row = sqlx::query!(
        r"SELECT m.id            AS id,
                 m.external_id   AS external_id,
                 m.auth_backend  AS auth_backend,
                 m.display_name  AS display_name,
                 m.pinned_admin  AS pinned_admin,
                 m.last_login_at AS last_login_at
          FROM moderators m
          WHERE m.external_id = $1 AND m.auth_backend = 'atproto'",
        did,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let roles: Vec<String> = sqlx::query_scalar!(
        r"SELECT role FROM moderator_roles WHERE moderator_id = $1 ORDER BY role ASC",
        row.id,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(Some(ModeratorDto {
        did: row.external_id,
        auth_backend: row.auth_backend,
        display_name: row.display_name,
        roles,
        pinned_admin: row.pinned_admin,
        last_login_at: row.last_login_at,
    }))
}

/// Count `admin` rows in `moderator_roles`. Used by the role-toggle
/// handler to refuse a revoke that would leave the deployment with
/// zero admins.
async fn count_admin_grants(pool: &PgPool) -> Result<i64, ApiError> {
    let count: i64 =
        sqlx::query_scalar!(r"SELECT count(*) FROM moderator_roles WHERE role = 'admin'",)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?
            .unwrap_or(0);
    Ok(count)
}

/// `GET /api/admin/moderators`.
///
/// Returns every moderator with their full role set, the pinned flag,
/// and the last-login timestamp.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::Internal`] on DB failure.
pub async fn list_moderators(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<Vec<ModeratorDto>>, ApiError> {
    require_admin(&ctx)?;
    let out = fetch_all_moderators(&state.pool).await?;
    Ok(Json(out))
}

/// `POST /api/admin/moderators`.
///
/// Resolves the supplied handle → DID via the same
/// [`proto_blue::identity::IdResolver`] the login dance uses, then
/// upserts the moderator row and the role-grant in a single
/// transaction. Re-POSTing the same `(handle, role)` pair is a
/// no-op (idempotent on the role-grant PK; the moderator-row upsert
/// updates `last_login_at` to `now()` only on conflict by design —
/// we deliberately do NOT touch `last_login_at` here because the
/// row is being created out-of-band, not via a login).
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] when the role string is unknown.
/// - [`ApiError::HandleResolutionFailed`] when the handle does not
///   resolve to a DID via the upstream PLC / DNS path.
/// - [`ApiError::Internal`] on DB or audit-log failure.
pub async fn add_moderator(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(req): Json<AddModeratorRequest>,
) -> Result<(StatusCode, Json<ModeratorDto>), ApiError> {
    require_admin(&ctx)?;
    let handle = req.handle.trim();
    if handle.is_empty() {
        return Err(ApiError::BadRequest("handle must not be empty"));
    }
    let role = parse_role(&req.role)?;

    // Resolve handle → DID through the shared identity resolver.
    // The resolver is owned by the atproto verifier; the OIDC
    // backend does not have one, so this endpoint is currently
    // atproto-only. A deployment running OIDC would manage its
    // moderators through the OIDC IdP directly.
    let verifier = state
        .moderator_auth
        .as_deref()
        .and_then(AnyModeratorAuth::as_atproto)
        .ok_or(ApiError::BadRequest(
            "moderator management requires the atproto OAuth backend",
        ))?;
    // Accept three input shapes so an admin can grant a role to
    // either a DID-typed identity (out-of-band verified) or a plain
    // handle (resolved through PLC + DNS with the alsoKnownAs
    // bidirectional check).
    let did: String = if handle.starts_with("did:") {
        // Trust the caller's typed DID directly. Resolving the DID
        // document would catch a typo'd DID but at the cost of a
        // round-trip every admin-add — the operator is the user
        // here, and the DID-document fetch is already exercised on
        // their own login. Accepting a bare DID matches Ozone's
        // shape (its `addMember` mutation takes a DID).
        handle.to_owned()
    } else {
        verifier
            .identity_resolver()
            .resolve_handle_verified(handle)
            .await
            .map(|(did, _doc)| did)
            .map_err(|_e| ApiError::HandleResolutionFailed {
                handle: handle.to_owned(),
            })?
    };

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let moderator_uuid: Uuid = sqlx::query_scalar!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'atproto')
          ON CONFLICT (auth_backend, external_id) DO UPDATE
            SET external_id = EXCLUDED.external_id
          RETURNING id",
        did,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    sqlx::query!(
        r"INSERT INTO moderator_roles (moderator_id, role, granted_by)
          VALUES ($1, $2, $3)
          ON CONFLICT (moderator_id, role) DO NOTHING",
        moderator_uuid,
        role.as_db_str(),
        ctx.moderator_id.0,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor: actor.clone(),
            kind: "moderator_added".to_owned(),
            payload: serde_json::json!({
                "target_did": did,
                "role": role.as_db_str(),
                "moderator_id": moderator_uuid.to_string(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    // Re-read the freshly-written row so the response carries the
    // canonical shape (including any pre-existing role rows the
    // upsert preserved).
    let dto = fetch_moderator_by_did(&state.pool, &did)
        .await?
        .ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!(
                "moderator row vanished between insert and read-back",
            ))
        })?;
    Ok((StatusCode::CREATED, Json(dto)))
}

/// `PATCH /api/admin/moderators/:did/roles`.
///
/// Toggles a single role on a moderator. The handler refuses two
/// pathological removals:
///
/// 1. Demoting the pinned bootstrap admin's `admin` role (the pin
///    exists precisely to prevent this).
/// 2. Demoting the last-admin's `admin` role (the deployment must
///    always retain at least one admin so a future operator can
///    log in).
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] when the role string is unknown.
/// - [`ApiError::NotFound`] when no moderator with the supplied DID
///   exists.
/// - [`ApiError::Conflict`] when the requested change would leave
///   zero admins OR would demote a pinned admin's admin role.
/// - [`ApiError::Internal`] on DB or audit-log failure.
pub async fn patch_moderator_roles(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(did): Path<String>,
    Json(req): Json<PatchRolesRequest>,
) -> Result<Json<ModeratorDto>, ApiError> {
    require_admin(&ctx)?;
    let role = parse_role(&req.role)?;

    let target = sqlx::query!(
        r"SELECT id, pinned_admin FROM moderators
          WHERE external_id = $1 AND auth_backend = 'atproto'",
        did,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?
    .ok_or(ApiError::NotFound)?;

    // Last-admin / pinned-admin guards apply only when we're about
    // to REVOKE the admin role.
    if !req.grant && role == Role::Admin {
        if target.pinned_admin {
            return Err(ApiError::Conflict(
                "cannot revoke admin from the pinned bootstrap admin",
            ));
        }
        let admin_count = count_admin_grants(&state.pool).await?;
        if admin_count <= 1 {
            return Err(ApiError::Conflict(
                "cannot remove the last admin; grant admin to another moderator first",
            ));
        }
    }

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    if req.grant {
        sqlx::query!(
            r"INSERT INTO moderator_roles (moderator_id, role, granted_by)
              VALUES ($1, $2, $3)
              ON CONFLICT (moderator_id, role) DO NOTHING",
            target.id,
            role.as_db_str(),
            ctx.moderator_id.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;
    } else {
        sqlx::query!(
            r"DELETE FROM moderator_roles
              WHERE moderator_id = $1 AND role = $2",
            target.id,
            role.as_db_str(),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;
    }

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "moderator_role_changed".to_owned(),
            payload: serde_json::json!({
                "target_did": did,
                "role": role.as_db_str(),
                "grant": req.grant,
                "moderator_id": target.id.to_string(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let dto = fetch_moderator_by_did(&state.pool, &did)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(dto))
}

/// `DELETE /api/admin/moderators/:did`.
///
/// Removes a moderator entirely. The FK cascade on
/// `moderator_roles.moderator_id` clears every role grant in one
/// statement; the audit-log entry is appended in the same
/// transaction so the deletion is recorded atomically.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::NotFound`] when no moderator with the supplied DID
///   exists.
/// - [`ApiError::Conflict`] when the target carries `pinned_admin =
///   TRUE`.
/// - [`ApiError::Internal`] on DB or audit-log failure.
pub async fn delete_moderator(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(did): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx)?;

    let target = sqlx::query!(
        r"SELECT id, pinned_admin FROM moderators
          WHERE external_id = $1 AND auth_backend = 'atproto'",
        did,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?
    .ok_or(ApiError::NotFound)?;

    if target.pinned_admin {
        return Err(ApiError::Conflict(
            "cannot delete the pinned bootstrap admin",
        ));
    }

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    sqlx::query!(r"DELETE FROM moderators WHERE id = $1", target.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "moderator_removed".to_owned(),
            payload: serde_json::json!({
                "target_did": did,
                "moderator_id": target.id.to_string(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use crate::auth::ModeratorId;
    use std::collections::HashSet;

    fn ctx_with(roles: &[Role]) -> ModeratorAuthCtx {
        ModeratorAuthCtx::new(
            ModeratorId::new_v4(),
            roles.iter().copied().collect::<HashSet<_>>(),
        )
    }

    #[test]
    fn require_admin_accepts_admin() {
        require_admin(&ctx_with(&[Role::Admin])).unwrap();
    }

    #[test]
    fn require_admin_rejects_non_admin() {
        let err = require_admin(&ctx_with(&[Role::SeniorModerator])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[Role::Moderator])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[Role::Triage])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[Role::ReadOnly])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn require_admin_rejects_empty_role_set() {
        let err = require_admin(&ctx_with(&[])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn parse_role_accepts_four_admin_facing_tiers() {
        assert!(matches!(parse_role("admin"), Ok(Role::Admin)));
        assert!(matches!(
            parse_role("senior_moderator"),
            Ok(Role::SeniorModerator)
        ));
        assert!(matches!(parse_role("moderator"), Ok(Role::Moderator)));
        assert!(matches!(parse_role("triage"), Ok(Role::Triage)));
    }

    #[test]
    fn parse_role_rejects_read_only_and_unknown() {
        assert!(matches!(
            parse_role("read_only"),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(parse_role(""), Err(ApiError::BadRequest(_))));
        assert!(matches!(
            parse_role("superuser"),
            Err(ApiError::BadRequest(_))
        ));
    }
}
