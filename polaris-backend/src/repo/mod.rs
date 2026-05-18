//! Repository layer: typed, compile-time-checked SQL over Postgres.
//!
//! Per `design.md` §4 and §6, every business-domain query goes through a
//! `*Repo` trait in this module. The trait is the contract; a `Pg*Repo`
//! struct is the only impl ferried into the rest of the binary today, but
//! M2+ tests will swap a fake impl in for handler tests without touching the
//! handler code.
//!
//! # Invariants
//!
//! - **Compile-time-checked SQL only.** Every query goes through
//!   `sqlx::query!` / `sqlx::query_as!`. No string-built SQL. No
//!   `query_unchecked`. The `.sqlx/` offline cache is regenerated whenever
//!   a query is added or modified.
//! - **Typed inputs and outputs.** Repos accept `New<Type>` inputs and return
//!   `polaris_types::*` outputs. The row-shape adapters (`fn row_to_subject`
//!   etc.) are private to each module so the DB column shape never bleeds
//!   into the repo's public surface.
//! - **No leaky `sqlx::Error`.** Every fallible repo method returns
//!   [`RepoError`]. The `?` operator converts `sqlx::Error` via
//!   [`From<sqlx::Error> for RepoError`] which inspects SQLSTATE and routes
//!   integrity-class failures to the corresponding variants
//!   ([`RepoError::UniqueViolation`], [`RepoError::ForeignKey`],
//!   [`RepoError::AppendOnlyViolation`]).
//! - **No `Arc<PgPool>`.** `sqlx::PgPool` is already internally `Arc`-shared.
//!   Each `Pg*Repo` holds the pool by value and clones it; cloning is cheap
//!   and propagates the same backing pool.
//! - **`actions` is append-only.** [`action::ActionRepo`] exposes only
//!   `insert` / `get` / `list_by_incident`. Any UPDATE against the `actions`
//!   table is rejected by a Postgres trigger (migration
//!   `00000000000004_actions.sql`). Tests prove this is total.
//!
//! # Trait dispatch shape
//!
//! Each repo trait uses `async fn` in trait (AFIT) — stable since Rust 1.75
//! and supported by our 1.88 toolchain without further ceremony. The
//! consequence is that `Pg*Repo` cannot today be used behind a `dyn Trait`;
//! handlers must accept a concrete `Pg*Repo` (or a generic `<R: SubjectRepo>`)
//! until either `trait_variant` stabilises or this module re-introduces the
//! `async-trait` macro for dyn dispatch. The architect's pre-flight notes on
//! `async-trait` in the workspace `Cargo.toml` anticipated dyn-compat; this
//! dispatch follows the AFIT path and surfaces the trade-off in the
//! completion report.
//!
//! # Layout
//!
//! - [`subject`] — [`subject::SubjectRepo`] + `PgSubjectRepo`.
//! - [`incident`] — [`incident::IncidentRepo`] + `PgIncidentRepo`.
//! - [`action`] — [`action::ActionRepo`] + `PgActionRepo` (append-only).
//! - [`report`] — [`report::ReportRepo`] + `PgReportRepo`.
//! - [`observation`] — [`observation::ObservationRepo`] + `PgObservationRepo`.

pub mod action;
pub mod action_policy_citations;
pub mod appeal;
pub mod federation;
pub mod incident;
pub mod llm_audit;
pub mod mod_policies;
pub mod observation;
pub mod pattern_action;
pub mod report;
pub mod second_opinion;
pub mod subject;

pub use action::{ActionRepo, NewAction, PgActionRepo};
pub use appeal::{
    AppealRepo, AppealRow, CalibrationEventRepo, NewAppeal, PgAppealRepo, PgCalibrationEventRepo,
};
pub use incident::{IncidentRepo, NewIncident, PgIncidentRepo};
pub use observation::{NewObservation, ObservationRepo, PgObservationRepo};
pub use pattern_action::{
    NewPatternActionHeader, PatternActionRepo, PatternActionRow, PatternActionStatus,
    PgPatternActionRepo,
};
pub use report::{NewReport, PgReportRepo, ReportRepo};
pub use second_opinion::{
    Message, MessageId, PgSecondOpinionRepo, SearchHit, SecondOpinionRepo, Thread, ThreadId,
};
pub use subject::{NewSubject, PgSubjectRepo, SubjectRepo};

/// Errors raised by the repository layer.
///
/// Variants are routed from `sqlx::Error` via the `From` impl below: SQLSTATE
/// `23505` becomes [`RepoError::UniqueViolation`], `23503` becomes
/// [`RepoError::ForeignKey`], and `P0001` (PL/pgSQL `RAISE EXCEPTION`, used
/// by the `actions` BEFORE UPDATE trigger) becomes
/// [`RepoError::AppendOnlyViolation`]. Anything else falls through to
/// [`RepoError::Database`].
///
/// `Decode` is raised by per-repo helpers when a DB row carries a value that
/// does not match a polaris-types enum's wire form (e.g. a `subjects.kind`
/// outside the CHECK-constrained set). It indicates schema drift, not user
/// input — surfacing it as a typed variant keeps callers from confusing it
/// with a transient connection failure.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// `SELECT` returned no row when the caller required exactly one.
    ///
    /// Note: most read methods on the repos return `Option<Type>` and use
    /// `None` as the "not found" channel; this variant is reserved for
    /// internal helpers (e.g. transactional re-reads) where a missing row
    /// implies an invariant violation upstream.
    #[error("row not found")]
    NotFound,
    /// A unique-constraint violation (SQLSTATE `23505`).
    #[error("unique constraint violation")]
    UniqueViolation(#[source] sqlx::Error),
    /// A foreign-key violation (SQLSTATE `23503`).
    #[error("foreign-key constraint violation")]
    ForeignKey(#[source] sqlx::Error),
    /// An attempted UPDATE against the append-only `actions` table.
    ///
    /// The Postgres trigger in migration `00000000000004_actions.sql` raises
    /// a PL/pgSQL exception (SQLSTATE `P0001`) on any UPDATE; this variant
    /// is how repos and tests assert that the invariant held.
    #[error("attempted UPDATE on append-only table")]
    AppendOnlyViolation(#[source] sqlx::Error),
    /// A DB row carried a value outside the polaris-types contract (e.g.
    /// an unknown enum-discriminator string). Indicates schema drift.
    #[error("failed to decode database row: {message}")]
    Decode {
        /// Diagnostic context (column name, offending value).
        message: String,
    },
    /// Any other database-level failure (connection lost, query syntax error,
    /// etc.).
    #[error("database error")]
    Database(#[source] sqlx::Error),
    /// Audit-log append failure surfaced through a repo path
    /// (issue #35). Wraps the [`crate::audit::AuditError`] so callers
    /// see the original chain-break / encoding category.
    #[error("audit-log append failed")]
    Audit(#[source] crate::audit::AuditError),
}

impl From<crate::audit::AuditError> for RepoError {
    fn from(err: crate::audit::AuditError) -> Self {
        match err {
            // Unwrap the inner sqlx::Error so SQLSTATE routing still
            // works for chain-break (P0001) and other database
            // failures triggered by the audit insert.
            crate::audit::AuditError::Db(e) => Self::from(e),
            other => Self::Audit(other),
        }
    }
}

impl From<sqlx::Error> for RepoError {
    fn from(err: sqlx::Error) -> Self {
        // `code()` returns a `Cow<'_, str>` — clone into an owned String once
        // so the match arms can borrow it as a `&str`.
        let code = err
            .as_database_error()
            .and_then(|d| d.code().map(std::borrow::Cow::into_owned));
        match code.as_deref() {
            Some("23505") => Self::UniqueViolation(err),
            Some("23503") => Self::ForeignKey(err),
            Some("P0001") => Self::AppendOnlyViolation(err),
            _ => Self::Database(err),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn repo_error_display_messages_are_stable() {
        // Stability check: the `Display` text on each variant is what shows
        // up in operator-facing logs. A future refactor that silently rewords
        // an `#[error("…")]` string is caught by these literal comparisons.
        assert_eq!(RepoError::NotFound.to_string(), "row not found");
        assert_eq!(
            RepoError::Decode {
                message: "kind=zzz".to_owned()
            }
            .to_string(),
            "failed to decode database row: kind=zzz",
        );
    }
}
