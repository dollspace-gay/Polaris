//! Polaris-internal types: Subject, Incident, Action, Observation, Report, Moderator.
//!
//! Plain Rust, serde-derived, no ATProto wire types. This crate is intentionally
//! free of any `proto-blue` dependency so that it can be imported by both
//! `polaris-backend` and `polaris-frontend` without pulling ATProto machinery
//! into the frontend's dependency graph ahead of schedule.
//!
//! # Crate Invariant
//!
//! **No `proto-blue` dependency, direct or transitive.**
//! Verify with `cargo tree -p polaris-types --depth 1` — `proto-blue` must
//! not appear. This invariant is enforced by the `Cargo.toml` dependency list
//! and tested in CI (AC-8).
//!
//! # Layout
//!
//! - [`ids`] — typed UUID newtypes plus the string newtypes `Did`, `AtUri`,
//!   `PolicyId`, `LabelValue`.
//! - [`subject`] — [`Subject`], [`SubjectKind`], [`Signal`], [`NewSubject`].
//! - [`incident`] — [`Incident`], [`IncidentStatus`], [`Severity`],
//!   [`NewIncident`].
//! - [`action`] — [`Action`], [`ActionKind`], [`NewAction`]. **Append-only**;
//!   no `reversed_by` field — reverse relations are derived at read time.
//! - [`report`] — [`Report`], [`ReportCategory`], [`NewReport`].
//! - [`observation`] — [`Observation`], [`ObservationKind`], [`NewObservation`].
//! - [`routing`] — [`RoutingCategory`], [`ModeratorSpecialty`],
//!   [`ExposureBudget`]. Routing-relevant typed inputs consumed by
//!   `polaris-backend`'s pure routing function (`design.md` §5.4).
//!
//! # Re-exports
//!
//! The crate re-exports the concrete types at the top level so consumers can
//! write `polaris_types::Subject` without remembering which submodule a type
//! lives in. The module structure remains visible for cases where it
//! matters (e.g. matching on `SubjectKind` next to other `subject`-module
//! constants).

pub mod action;
pub mod appeal;
pub mod ids;
pub mod incident;
pub mod observation;
pub mod report;
pub mod routing;
pub mod subject;

pub use action::{Action, ActionKind, NewAction};
pub use appeal::{
    AppealDecision, AppealId, AppealStatus, CalibrationEvent, CalibrationEventKind,
    InvalidTransition,
};
pub use ids::{
    ActionId, AtUri, Did, IncidentId, LabelValue, ModeratorId, ObservationId, PatternActionId,
    PolicyId, ReportId, SubjectId,
};
pub use incident::{Incident, IncidentStatus, NewIncident, Severity};
pub use observation::{NewObservation, Observation, ObservationKind};
pub use report::{NewReport, Report, ReportCategory};
pub use routing::{ExposureBudget, ModeratorSpecialty, RoutingCategory};
pub use subject::{NewSubject, Signal, Subject, SubjectKind};
