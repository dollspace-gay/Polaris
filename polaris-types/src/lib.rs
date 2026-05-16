//! Polaris-internal types: Subject, Incident, Action, Observation, Report, Moderator.
//!
//! Plain Rust, serde-derived, no ATProto wire types in the domain modules
//! (`subject`, `incident`, `action`, `observation`, `report`, `routing`,
//! `appeal`, `ids`). Those modules stay proto-blue-free so a future
//! "lift them onto a target without proto-blue" move stays a single-
//! module refactor.
//!
//! # Dependency policy
//!
//! The historical AC-8 rule was "no `proto-blue` dependency, direct or
//! transitive." Issue #61 relaxes that to **one carve-out, one module**:
//! the [`oauth_config`] loader returns a `proto_blue::oauth::ClientMetadata`
//! value so the two consumers (the moderator ATProto OAuth verifier,
//! [`polaris_backend::auth::atproto`][backend], and the
//! `polaris-publish-labeler-record` CLI's `--oauth` flow) share one
//! canonical read-and-parse path. `polaris-frontend` already depends on
//! `proto-blue` at the workspace level, so the frontend's dependency
//! graph is unchanged by this edit.
//!
//! See `polaris-types/Cargo.toml` for the policy block reviewers should
//! consult before adding any other proto-blue-typed item to this crate.
//!
//! [backend]: ../polaris_backend/auth/atproto/index.html
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
//! - [`oauth_config`] — shared `load_client_metadata` loader (#61).
//!   The *only* module in this crate that references a `proto-blue` type.
//! - [`escalation`] — [`Escalation`], [`EmbeddedObservation`], [`SubjectRef`].
//!   Cross-instance federation record for pattern evidence (#103 / M5 PR 3).
//! - [`evidence`] — [`EvidencePointer`]. Content-addressed CAR file pointer
//!   embedded in escalations.
//! - [`lexicon_mapping`] — mapping functions between internal types and the
//!   `polaris-lexicons` wire types. The *only* module that references
//!   `polaris-lexicons`.
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
pub mod escalation;
pub mod evidence;
pub mod ids;
pub mod incident;
pub mod lexicon_mapping;
pub mod oauth_config;
pub mod observation;
pub mod report;
pub mod routing;
pub mod subject;

pub use action::{Action, ActionKind, NewAction};
pub use appeal::{
    AppealDecision, AppealId, AppealStatus, CalibrationEvent, CalibrationEventKind,
    InvalidTransition,
};
pub use escalation::{EmbeddedObservation, Escalation, SubjectRef};
pub use evidence::EvidencePointer;
pub use ids::{
    ActionId, AtUri, Did, EscalationId, IncidentId, LabelValue, ModeratorId, ObservationId,
    PatternActionId, PolicyId, ReportId, SubjectId,
};
pub use incident::{Incident, IncidentStatus, NewIncident, Severity};
pub use observation::{NewObservation, Observation, ObservationKind};
pub use report::{NewReport, Report, ReportCategory};
pub use routing::{ExposureBudget, ModeratorSpecialty, RoutingCategory};
pub use subject::{NewSubject, Signal, Subject, SubjectKind};
