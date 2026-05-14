//! Pattern-dashboard subcomponents (issue #20).
//!
//! Each submodule defines one `#[component]` rendering one of the four
//! panels described in `design.md` §5.1:
//!
//! - [`report_volume_chart`] — SVG sparkline + anomaly band over the
//!   trailing 24h hourly buckets.
//! - [`cluster_list`] — top incidents ranked by `severity × reach`,
//!   each row a drill-down link to the case view.
//! - [`coordinated_signals`] — recent cohort / image-hash / brigade
//!   observations, with kind icon + label.
//! - [`moderator_load`] — bar-chart-ish per-category queue depth.
//!
//! The page-level [`crate::pages::dashboard::PatternDashboard`] owns the
//! polling [`leptos::prelude::Resource`] and threads slices of the
//! [`crate::api_client::dto::DashboardSnapshot`] into each component as
//! plain props. Components are presentation-only; they do not own a
//! `PolarisApiClient` handle.

pub mod cluster_list;
pub mod coordinated_signals;
pub mod moderator_load;
pub mod report_volume_chart;
