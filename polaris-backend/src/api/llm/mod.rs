//! LLM moderation-assist API surface
//! (`.design/llm-moderation-assist.md`, issue #242 / LLM-5).
//!
//! Today the surface is a single endpoint —
//! `POST /api/cases/:case_id/llm-recommendation` — that drives the
//! [`crate::llm::recommend_dispatcher::RecommendDispatcher`] for a
//! moderator-initiated `Pull` trigger. The admin surfaces (audit
//! list, dry-run, kill-switch) land in separate issues (#238,
//! #240, #241) and will mount sibling modules under
//! [`crate::api::llm`].

pub mod case_endpoint;
