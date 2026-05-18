//! LLM moderation-assist API surface
//! (`.design/llm-moderation-assist.md`).
//!
//! Three modules:
//!
//! - [`case_endpoint`] — moderator-initiated `Pull` trigger
//!   (`POST /api/cases/:case_id/llm-recommendation`; issue #242 /
//!   LLM-5).
//! - [`admin_audit`] — admin audit list of autonomous actions with
//!   their full LLM envelope (`GET /api/admin/llm/audit`; LLM-9 /
//!   #238).
//! - [`admin_pause`] — global kill switch (REQ-S7; issue #241 /
//!   LLM-12). `POST`/`DELETE` `/api/admin/llm/pause` toggles
//!   `polaris_setup_state.global_autonomous_pause_until`.
//!
//! The remaining admin surface — dry-run calibration (#240) — will
//! mount a sibling module here.

pub mod admin_audit;
pub mod admin_pause;
pub mod case_endpoint;
