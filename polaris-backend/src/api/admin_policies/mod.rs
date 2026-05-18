//! Admin policy-workbook REST surface (WB-3 / issue #225).
//!
//! Routes mounted under `/api/admin/policies/*`. Route registration
//! happens in [`crate::api::authed_router`] alongside the rest of the
//! admin surface (`admin_moderators` and the upcoming admin pages)
//! so the auth-middleware layer covers them uniformly.
//!
//! # Route ordering
//!
//! axum's matcher is greedy: a `:identifier/:version` route registered
//! before `:identifier/history` or `:identifier/diff` would consume
//! the literal words `history` / `diff` as a version path parameter.
//! The composer in `crate::api::authed_router` therefore registers
//! the more-specific literal routes FIRST and the catch-all
//! `:identifier/:version` last, so the greedy matcher sees the literal
//! paths before the wildcard.

pub mod dto;
pub mod handlers;

pub use dto::{
    CreatePolicyDto, DiffChangeDto, ModPolicyDto, ModPolicyEditDto, ModPolicyHistoryEntryDto,
    ModPolicySummaryDto, PausePolicyDto, PolicyDiffDto,
};
pub use handlers::{
    DiffQuery, ListPoliciesQuery, create_admin_policy, get_admin_policy,
    get_admin_policy_at_version, get_admin_policy_diff, get_admin_policy_history,
    list_admin_policies, patch_admin_policy, pause_admin_policy, resume_admin_policy,
};
