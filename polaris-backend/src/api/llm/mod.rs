//! LLM moderation-assist API surface
//! (`.design/llm-moderation-assist.md`).
//!
//! Four modules:
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
//! - [`admin_dry_run`] — calibration replay (REQ-H; issue #240 /
//!   LLM-11). `POST /api/admin/llm/dry-run` kicks off a job that
//!   replays closed incidents through the LLM in no-side-effect
//!   mode; `GET /api/admin/llm/dry-run/{job_id}` polls progress
//!   and returns the agreement-rate aggregate.

pub mod admin_audit;
pub mod admin_dry_run;
pub mod admin_pause;
pub mod case_endpoint;
