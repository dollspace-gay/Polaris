//! Routing helpers.
//!
//! The routing table itself lives in [`crate::app`] alongside the
//! `<Router/>` mount. This module is reserved for routing-adjacent
//! helpers (typed route constants, query-string codecs) that grow as
//! navigation surface area expands.
//!
//! The previous `dashboard` submodule (the M0 scaffolding from #10) was
//! superseded by [`crate::pages::dashboard::PatternDashboard`] in #20 —
//! the real pattern dashboard described in `design.md` §5.1.
