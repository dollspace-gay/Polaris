//! Faceted-filter parsing for `GET /api/dashboard` (issue #94 / mod-
//! workstation feature #4).
//!
//! The dashboard handler accepts four optional facet parameters
//! ([`reporter_did`][DashboardQuery::reporter_did],
//! [`category`][DashboardQuery::category],
//! [`status`][DashboardQuery::status],
//! [`since`][DashboardQuery::since] / [`until`][DashboardQuery::until]).
//! This module owns the pure validation helpers that convert raw query
//! strings into typed values (`Did` / `IncidentStatus` /
//! `DateTime<Utc>`).
//!
//! Each helper is pure (no DB, no clock, no async) so it is unit-
//! testable on native without a runtime, satisfying AC-2.
//!
//! # Date column note
//!
//! The spec calls out filtering `incidents.created_at` by the
//! `since` / `until` window, but the on-disk schema (migration
//! `00000000000003_subjects_incidents.sql`) names the column
//! `opened_at`. The SQL in the handler uses the real column name; this
//! module is only concerned with parsing the wire input.

use chrono::{DateTime, Utc};
use polaris_types::IncidentStatus;
use proto_blue::syntax::Did as ProtoDid;
use serde::Deserialize;

// ── Wire shape ─────────────────────────────────────────────────────────

/// Query-string facet payload for `GET /api/dashboard`.
///
/// Every field is optional; an empty `DashboardQuery` is the
/// backward-compatible default (matches the pre-#94 unfiltered response
/// shape verbatim). Axum's `Query<DashboardQuery>` extractor decodes
/// the URL parameters into this struct.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DashboardQuery {
    /// Filter incidents to those whose `reports.reporter_did` matches
    /// this DID. Validated against [`ProtoDid::new`] before reaching
    /// SQL — malformed input surfaces as `400 bad_request`.
    pub reporter_did: Option<String>,
    /// Filter incidents to those with at least one report in this
    /// category. Categories are free-form strings defined by the
    /// reporting lexicon — pass-through with no enum gate.
    pub category: Option<String>,
    /// Filter incidents by `incidents.status`. Wire form is the same
    /// lowercase-snake serde representation
    /// [`IncidentStatus::as_str`] produces.
    pub status: Option<String>,
    /// Lower bound on `incidents.opened_at` (inclusive). RFC3339
    /// timestamp.
    pub since: Option<String>,
    /// Upper bound on `incidents.opened_at` (inclusive). RFC3339
    /// timestamp.
    pub until: Option<String>,
}

impl DashboardQuery {
    /// Comma-joined list of active facet names, for the
    /// `polaris_dashboard_filtered_requests_total{filter}` Prometheus
    /// counter. Returns `"none"` when no facet is set (matches the
    /// spec's `filter=none` value for unfiltered requests).
    ///
    /// Order is canonical (`reporter_did`, `category`, `status`,
    /// `date_range`) so the metric cardinality stays bounded — there
    /// are at most 2^4 distinct labels.
    #[must_use]
    pub fn active_facet_label(&self) -> String {
        let mut parts: Vec<&'static str> = Vec::new();
        if self.reporter_did.as_deref().is_some_and(|s| !s.is_empty()) {
            parts.push("reporter_did");
        }
        if self.category.as_deref().is_some_and(|s| !s.is_empty()) {
            parts.push("category");
        }
        if self.status.as_deref().is_some_and(|s| !s.is_empty()) {
            parts.push("status");
        }
        if self.since.as_deref().is_some_and(|s| !s.is_empty())
            || self.until.as_deref().is_some_and(|s| !s.is_empty())
        {
            parts.push("date_range");
        }
        if parts.is_empty() {
            "none".to_owned()
        } else {
            parts.join(",")
        }
    }
}

// ── Parsed shape ───────────────────────────────────────────────────────

/// Result of parsing a [`DashboardQuery`] into typed facet values.
///
/// `None` fields encode "facet not active"; the SQL layer feeds them
/// through `$N IS NULL OR …` clauses so a single compile-time-checked
/// statement handles every facet combination.
#[derive(Debug, Clone, Default)]
pub struct ParsedFilters {
    /// Validated reporter DID. The SQL binds the string form.
    pub reporter_did: Option<String>,
    /// Pass-through category string.
    pub category: Option<String>,
    /// Validated incident status filter. When `None`, the handler
    /// applies the default `open + in_review + escalated` predicate
    /// (matches the pre-#94 default).
    pub status: Option<IncidentStatus>,
    /// Lower bound (inclusive) on `incidents.opened_at`.
    pub since: Option<DateTime<Utc>>,
    /// Upper bound (inclusive) on `incidents.opened_at`.
    pub until: Option<DateTime<Utc>>,
}

// ── Error type ─────────────────────────────────────────────────────────

/// Typed parse failure for the dashboard query string.
///
/// Each variant carries a static `&'static str` message so it can be
/// folded directly into [`crate::api::error::ApiError::BadRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FilterParseError {
    /// `reporter_did` failed `proto_blue::syntax::Did` validation.
    #[error("reporter_did is not a well-formed DID")]
    InvalidReporterDid,
    /// `status` is not one of the known [`IncidentStatus`] tokens.
    #[error("status must be one of open|in_review|actioned|closed|escalated")]
    UnknownStatus,
    /// `since` failed RFC3339 parsing.
    #[error("since is not a well-formed RFC3339 timestamp")]
    InvalidSince,
    /// `until` failed RFC3339 parsing.
    #[error("until is not a well-formed RFC3339 timestamp")]
    InvalidUntil,
    /// `since` > `until` — the range is inverted and matches no rows
    /// by construction; reject at the boundary so the moderator sees
    /// the typo rather than an empty list.
    #[error("since must be earlier than until")]
    InvertedRange,
}

impl FilterParseError {
    /// Static-string form for [`crate::api::error::ApiError::BadRequest`].
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidReporterDid => "reporter_did is not a well-formed DID",
            Self::UnknownStatus => "status must be one of open|in_review|actioned|closed|escalated",
            Self::InvalidSince => "since is not a well-formed RFC3339 timestamp",
            Self::InvalidUntil => "until is not a well-formed RFC3339 timestamp",
            Self::InvertedRange => "since must be earlier than until",
        }
    }
}

// ── Pure helpers ───────────────────────────────────────────────────────

/// Validate a reporter-DID query parameter.
///
/// Wraps `proto_blue::syntax::Did::new` so the wire-level grammar (the
/// AT-protocol DID syntax) is enforced before the value reaches SQL.
/// Returns the trimmed string form on success so the caller can bind
/// it directly to `sqlx::query!` without re-stringifying through
/// `Display`.
pub fn validate_reporter_did(value: &str) -> Result<String, FilterParseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FilterParseError::InvalidReporterDid);
    }
    ProtoDid::new(trimmed).map_err(|_| FilterParseError::InvalidReporterDid)?;
    Ok(trimmed.to_owned())
}

/// Validate a status filter value.
///
/// Wraps [`IncidentStatus::from_wire`] so the gate matches the existing
/// `/api/cases?status=…` filter wire form (`open` / `in_review` /
/// `actioned` / `closed` / `escalated`).
pub fn validate_status(value: &str) -> Result<IncidentStatus, FilterParseError> {
    let trimmed = value.trim();
    IncidentStatus::from_wire(trimmed).ok_or(FilterParseError::UnknownStatus)
}

/// Inclusive time-range pair produced by [`parse_since_until`]. The
/// pair shape `(since, until)` mirrors the URL query parameters; a
/// `None` on either side means "unbounded on that edge". Aliased so
/// the `clippy::type_complexity` lint doesn't flag the nested
/// `Option<DateTime<Utc>>` tuple in the function signature.
pub type ParsedTimeRange = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// Validate the `since` / `until` pair.
///
/// Each component is parsed via [`DateTime::parse_from_rfc3339`] (NOT
/// a regex — the forbidden-pattern list rules out regex parsing of
/// timestamps). When both are present, the inverted-range check
/// (`since` ≤ `until`) runs before either value is returned.
pub fn parse_since_until(
    since: Option<&str>,
    until: Option<&str>,
) -> Result<ParsedTimeRange, FilterParseError> {
    let parsed_since = match since {
        Some(raw) if !raw.is_empty() => Some(parse_rfc3339(raw, FilterParseError::InvalidSince)?),
        _ => None,
    };
    let parsed_until = match until {
        Some(raw) if !raw.is_empty() => Some(parse_rfc3339(raw, FilterParseError::InvalidUntil)?),
        _ => None,
    };
    if let (Some(s), Some(u)) = (parsed_since, parsed_until) {
        if s > u {
            return Err(FilterParseError::InvertedRange);
        }
    }
    Ok((parsed_since, parsed_until))
}

/// Helper: parse one RFC3339 timestamp into `DateTime<Utc>`, mapping
/// failures to the supplied [`FilterParseError`] variant.
fn parse_rfc3339(raw: &str, err: FilterParseError) -> Result<DateTime<Utc>, FilterParseError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| err)
}

/// Compose [`ParsedFilters`] from the raw [`DashboardQuery`].
///
/// One-stop validator the handler calls before SQL. Each facet feeds
/// through its specific helper so individual rejection paths are
/// preserved in the returned [`FilterParseError`].
pub fn parse_query(query: &DashboardQuery) -> Result<ParsedFilters, FilterParseError> {
    let reporter_did = match query.reporter_did.as_deref() {
        Some(value) if !value.is_empty() => Some(validate_reporter_did(value)?),
        _ => None,
    };
    let category = query
        .category
        .as_deref()
        .filter(|c| !c.is_empty())
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty());
    let status = match query.status.as_deref() {
        Some(value) if !value.is_empty() => Some(validate_status(value)?),
        _ => None,
    };
    let (since, until) = parse_since_until(query.since.as_deref(), query.until.as_deref())?;
    Ok(ParsedFilters {
        reporter_did,
        category,
        status,
        since,
        until,
    })
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

    // ── validate_reporter_did ───────────────────────────────────────

    #[test]
    fn validate_reporter_did_accepts_plc_form() {
        let did = validate_reporter_did("did:plc:z72i7hdynmk6r22z27h6tvur").expect("plc DID valid");
        assert_eq!(did, "did:plc:z72i7hdynmk6r22z27h6tvur");
    }

    #[test]
    fn validate_reporter_did_rejects_garbage() {
        let err = validate_reporter_did("not-a-did").expect_err("must reject");
        assert_eq!(err, FilterParseError::InvalidReporterDid);
    }

    #[test]
    fn validate_reporter_did_rejects_empty_after_trim() {
        let err = validate_reporter_did("   ").expect_err("must reject empty");
        assert_eq!(err, FilterParseError::InvalidReporterDid);
    }

    // ── validate_status ─────────────────────────────────────────────

    #[test]
    fn validate_status_accepts_open() {
        let status = validate_status("open").expect("open is a valid status");
        assert_eq!(status, IncidentStatus::Open);
    }

    #[test]
    fn validate_status_accepts_escalated() {
        let status = validate_status("escalated").expect("escalated valid");
        assert_eq!(status, IncidentStatus::Escalated);
    }

    #[test]
    fn validate_status_rejects_unknown() {
        let err = validate_status("on_fire").expect_err("must reject");
        assert_eq!(err, FilterParseError::UnknownStatus);
    }

    // ── parse_since_until ───────────────────────────────────────────

    #[test]
    fn parse_since_until_accepts_well_formed_pair() {
        let (since, until) =
            parse_since_until(Some("2026-05-01T00:00:00Z"), Some("2026-05-15T00:00:00Z"))
                .expect("well-formed pair");
        assert!(since.is_some());
        assert!(until.is_some());
        assert!(since.unwrap() < until.unwrap());
    }

    #[test]
    fn parse_since_until_rejects_malformed_since() {
        let err = parse_since_until(Some("not-a-date"), None).expect_err("must reject");
        assert_eq!(err, FilterParseError::InvalidSince);
    }

    #[test]
    fn parse_since_until_rejects_inverted_range() {
        let err = parse_since_until(Some("2026-05-15T00:00:00Z"), Some("2026-05-01T00:00:00Z"))
            .expect_err("must reject inverted range");
        assert_eq!(err, FilterParseError::InvertedRange);
    }

    #[test]
    fn parse_since_until_accepts_only_since() {
        let (since, until) =
            parse_since_until(Some("2026-05-01T00:00:00Z"), None).expect("only since is fine");
        assert!(since.is_some());
        assert!(until.is_none());
    }

    #[test]
    fn parse_since_until_treats_empty_as_absent() {
        let (since, until) = parse_since_until(Some(""), Some("")).expect("empty == none");
        assert!(since.is_none());
        assert!(until.is_none());
    }

    // ── active_facet_label ──────────────────────────────────────────

    #[test]
    fn active_facet_label_none_when_empty() {
        let q = DashboardQuery::default();
        assert_eq!(q.active_facet_label(), "none");
    }

    #[test]
    fn active_facet_label_lists_active_facets() {
        let q = DashboardQuery {
            reporter_did: Some("did:plc:abc".to_owned()),
            category: Some("spam".to_owned()),
            status: None,
            since: None,
            until: None,
        };
        assert_eq!(q.active_facet_label(), "reporter_did,category");
    }

    #[test]
    fn active_facet_label_collapses_date_range() {
        // Either of since/until counts as the single `date_range`
        // facet — the metric cardinality stays bounded.
        let q = DashboardQuery {
            since: Some("2026-05-01T00:00:00Z".to_owned()),
            ..DashboardQuery::default()
        };
        assert_eq!(q.active_facet_label(), "date_range");
    }

    // ── parse_query (composition) ───────────────────────────────────

    #[test]
    fn parse_query_returns_default_for_empty_input() {
        let q = DashboardQuery::default();
        let parsed = parse_query(&q).expect("empty query parses");
        assert!(parsed.reporter_did.is_none());
        assert!(parsed.category.is_none());
        assert!(parsed.status.is_none());
        assert!(parsed.since.is_none());
        assert!(parsed.until.is_none());
    }

    #[test]
    fn parse_query_propagates_first_error() {
        let q = DashboardQuery {
            reporter_did: Some("garbage".to_owned()),
            ..DashboardQuery::default()
        };
        let err = parse_query(&q).expect_err("must reject");
        assert_eq!(err, FilterParseError::InvalidReporterDid);
    }
}
