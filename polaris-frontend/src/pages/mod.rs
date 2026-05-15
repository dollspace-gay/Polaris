//! Routed pages (top-level views).
//!
//! Each submodule defines one `#[component]` mounted by the router in
//! [`crate::app`]. Pages compose smaller pieces from
//! [`crate::components`] and own the page-level [`leptos::prelude::LocalResource`]
//! that drives the data fetch. Components stay free of routing concerns;
//! pages stay free of presentation concerns. The two compose at the page
//! boundary.

pub mod case_view;
pub mod dashboard;
pub mod login;
pub mod setup;
