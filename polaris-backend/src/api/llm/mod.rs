//! LLM moderation-assist API surface
//! (`.design/llm-moderation-assist.md`).
//!
//! Two modules today:
//!
//! - [`case_endpoint`] — moderator-initiated `Pull` trigger
//!   (`POST /api/cases/:case_id/llm-recommendation`; issue #242 /
//!   LLM-5).
//! - [`admin_pause`] — global kill switch (REQ-S7; issue #241 /
//!   LLM-12). `POST/DELETE /api/admin/llm/pause` toggles
//!   `polaris_setup_state.global_autonomous_pause_until`.
//!
//! The remaining admin surfaces — audit list (#238), dry-run
//! (#240) — will mount sibling modules here.

pub mod admin_pause;
pub mod case_endpoint;
