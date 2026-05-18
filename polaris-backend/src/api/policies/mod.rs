//! Moderator-facing read-only policy browse surface (REQ-D4 / #225).
//!
//! Mounted under `/api/policies/*`. Write paths live under
//! `/api/admin/policies/*` in [`crate::api::admin_policies`]; this
//! module is intentionally read-only. The RBAC floor is
//! `Role::Moderator` or higher — anyone who can take a moderation
//! action can look up the rules they're enforcing.
//!
//! Route registration happens in [`crate::api::authed_router`] so
//! the auth-middleware layer covers these routes uniformly with
//! the rest of `/api/*`.

pub mod handlers;

pub use handlers::{get_policy, list_policies};
