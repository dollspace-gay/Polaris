//! Reusable view components for the case view (issue #15).
//!
//! Each submodule defines one `#[component]` plus its tightly-coupled
//! helpers. The page in [`crate::pages::case_view`] wires them together;
//! every component owns its own signals and accepts the minimum slice of
//! state through props (no global stores, no over-broad `Resource` hand-
//! offs).
//!
//! # Pattern locked here
//!
//! Per the issue #15 pre-flight:
//!
//! - One `Resource` per fetch, rendered inside `<Suspense>` + `<ErrorBoundary>`.
//! - No panicking constructs in non-test code (see forbidden-pattern
//!   checklist on issue #15).
//! - No `tokio` — async runs on `wasm-bindgen-futures` in the browser and
//!   nowhere on native (the native build is for `cargo check` only).
//! - Keyboard-first interactions: every actionable list supports `j`/`k`
//!   navigation; the action composer supports `Cmd-Enter` / `Ctrl-Enter`
//!   submit.
//! - Accessibility: ARIA roles on lists, label-input pairing on form
//!   fields, no color-only signals.

pub mod action_composer;
pub mod dashboard;
pub mod history_timeline;
pub mod network_panel;
pub mod report_list;
pub mod subject_header;
