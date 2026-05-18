//! Assisted-mode moderator queue API surface
//! (`.design/llm-moderation-assist.md` §E).
//!
//! The queue endpoints — list / approve / reject pending drafts —
//! land in LLM-7 (#236). This module is the structural anchor those
//! endpoints will hang off of; today it carries only the feedback
//! hook stub (LLM-10 / #239) the reject handler will call.
//!
//! See [`pending_auto_actions`] for the assisted-reject feedback
//! plumbing.

pub mod pending_auto_actions;
