//! Historical home of the `KNOWN_POLICY_REFS` placeholder slice.
//!
//! WB-2 (#224) replaced the slice with a runtime lookup against the
//! versioned `mod_policies` workbook. Callers that previously consulted
//! `is_known_policy_ref` should now read
//! [`crate::repo::mod_policies::current_by_identifier`] (typically
//! through [`crate::api::policy_cache::get_current`] on the hot
//! action-create path). The module is kept as an empty shim so existing
//! `use crate::api::policy;` imports continue to resolve until they are
//! migrated.
