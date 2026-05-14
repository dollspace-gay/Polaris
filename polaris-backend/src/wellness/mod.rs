//! Wellness instrumentation per `design.md` §5.7.
//!
//! Tracks per-moderator exposure to graphic content. Moderators set their
//! own daily caps, see their own running counts, and choose whether to
//! share an aggregate breakdown with management. The router consults the
//! same data to decide whether a moderator has remaining budget for new
//! graphic-content assignments (issue #22's `exposure_budget_remaining`).
//!
//! # Privacy invariant
//!
//! Exposure data is **moderator-first**. The single API path for
//! aggregate visibility, [`exposure::ExposureTracker::aggregate_for_manager`],
//! takes the consent flag as input. When `consent` is false the function
//! returns an empty vector regardless of caller intent. No other code path
//! exposes aggregate counts — this is the load-bearing invariant of §5.7
//! and is enforced at the trait level so a future caller cannot
//! accidentally leak by passing the wrong argument set.
//!
//! Self-view (the moderator looking at their own data) goes through
//! [`exposure::ExposureTracker::status_for_me`], which never inspects
//! consent because the caller is the data subject.
//!
//! # Module layout
//!
//! - [`exposure`] — the [`exposure::ExposureTracker`] facade over the
//!   `moderator_exposure` + `moderator_exposure_settings` tables.

pub mod exposure;

/// Errors raised by the wellness module.
#[derive(Debug, thiserror::Error)]
pub enum WellnessError {
    /// Postgres-layer failure (connection, decode, syntax error). The
    /// underlying [`sqlx::Error`] is preserved via `#[source]` so the cause
    /// chain renders in operator logs.
    #[error("database error")]
    Database(#[source] sqlx::Error),
    /// The moderator id passed to a write path did not match any row in
    /// `moderators`. Read paths return defaults rather than this error so
    /// the self-view stays render-able on a fresh moderator with no
    /// settings row yet.
    #[error("moderator not found")]
    NotFound,
}
