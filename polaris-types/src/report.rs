//! [`Report`] — an individual user-submitted report.
//!
//! Per `design.md` §5.2: a report is a *signal* that contributes to an
//! incident; reports aggregate to subjects, subjects cluster into incidents.
//! Twelve reports against one account become one incident with twelve
//! attached reports, not twelve cases.
//!
//! The `reports` table is time-partitioned monthly (see migration
//! `00000000000005_reports.sql`) so that the §4 "age out to cold storage
//! after 18 months" lifecycle is implementable by dropping or detaching old
//! partitions rather than walking individual rows.

use chrono::{DateTime, Utc};

use crate::ids::{Did, IncidentId, ReportId, SubjectId};

/// ATProto-style report category. Polaris stores the wire string verbatim
/// (categories evolve faster than schema migrations) and validates against
/// the operator's configured allow-list at the API boundary, not here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ReportCategory(pub String);

impl ReportCategory {
    /// Construct a [`ReportCategory`] from any string-like value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ReportCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<String> for ReportCategory {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ReportCategory {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// An individual user-submitted report.
///
/// Maps 1:1 with a row in the `reports` partitioned table.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Report {
    /// Polaris-internal identifier.
    pub id: ReportId,
    /// Subject this report is about.
    pub subject_id: SubjectId,
    /// Incident this report has been aggregated into. `None` means the report
    /// is still unaggregated (the ingest pipeline hasn't bound it to a
    /// subject's open incident yet).
    pub incident_id: Option<IncidentId>,
    /// DID of the account that submitted the report.
    pub reporter_did: Did,
    /// Report category — see [`ReportCategory`].
    pub category: ReportCategory,
    /// Free-text body submitted by the reporter.
    pub body: String,
    /// When the report was received.
    pub created_at: DateTime<Utc>,
}

/// Caller-supplied fields for inserting a new [`Report`].
///
/// The repo populates `id` and `created_at`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NewReport {
    /// Subject the report is about.
    pub subject_id: SubjectId,
    /// Incident binding (typically `None` at insert time; the aggregation
    /// pipeline links it later).
    pub incident_id: Option<IncidentId>,
    /// Reporter DID.
    pub reporter_did: Did,
    /// Category.
    pub category: ReportCategory,
    /// Body text.
    pub body: String,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn report_category_round_trips_as_string() {
        let c = ReportCategory::new("spam");
        let json = serde_json::to_string(&c).expect("serialize");
        assert_eq!(json, "\"spam\"");
        let back: ReportCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, back);
    }
}
