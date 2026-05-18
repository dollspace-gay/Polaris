//! LLM moderation-assist subsystem
//! (`.design/llm-moderation-assist.md`, issue #231).
//!
//! This module groups the read-side of the LLM pipeline (case
//! context hydration, #234) with its writer counterparts (the
//! dispatcher #242, safety floors #235, dry-run job #237) as they
//! land. Today only [`case_context`] is shipped; the remaining
//! sub-modules attach to this root in their own PRs without
//! disturbing the existing call surface.
//!
//! # Privacy floor
//!
//! Per `.design/llm-moderation-assist.md` REQ-A2: the wire
//! `RecommendRequest` the LLM adapter sees NEVER carries moderator
//! identities. The `case_context::hydrate` function below enforces
//! this structurally — the proto `PriorAction` message has no
//! `moderator_id` field, so a leak is a compile error, not a runtime
//! audit failure. Future hydrators added to this module are expected
//! to honour the same boundary; see the per-call doc comments for
//! the specific shape each emits.

pub mod case_context;
pub mod feedback;
pub mod recommend_dispatcher;
pub mod safety_floors;
