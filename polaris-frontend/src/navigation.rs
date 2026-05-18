//! Shared client-side navigation primitives.
//!
//! Multiple call sites need to jump the moderator to
//! `/cases/<subject_id>` — the queue's `o` keybind, the subject-
//! lookup bar's Open button, the network panel's actor-pivot
//! button, and (future) the related-actions timeline rows. Each
//! used to roll its own wasm dispatch + native stub, which left
//! the codebase with three slightly-different implementations and
//! a fistful of dead native stubs.
//!
//! [`navigate_to_case`] is the single canonical helper. On wasm it
//! issues a hard browser navigation via `window.location.assign`
//! — the same primitive every prior implementation eventually fell
//! back to — so it works inside `spawn_local` async contexts where
//! `leptos_router::use_navigate()` would panic (it requires a
//! reactive owner that detached tasks do not have).
//!
//! On native it logs the would-be navigation at `info!` (via
//! `tracing`) so test runs surface the call shape rather than
//! dropping it on the floor silently. The native path is genuinely
//! exercised — it's not target-gated — which means the function is
//! reachable from every build and no `#[allow(dead_code)]` is
//! needed.

#[cfg(not(target_arch = "wasm32"))]
use tracing::info;

/// Push the moderator's browser to `/cases/<subject_id>`.
///
/// On wasm this triggers a hard navigation; the SPA re-bootstraps
/// on the destination route, which guarantees the case-view's
/// `LocalResource` runs from scratch. On native (test / IDE check
/// builds) this logs the intent and returns; tests can drive the
/// function and assert that the call site fires without setting
/// up a browser harness.
///
/// `subject_id` is the UUID-string form of [`polaris_types::SubjectId`]
/// — i.e., the same shape that fits in the `/cases/:subject_id`
/// route segment.
pub fn navigate_to_case(subject_id: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        let href = format!("/cases/{subject_id}");
        if let Some(window) = web_sys::window() {
            // `Result` is intentionally dropped: a navigation failure
            // is operationally fatal (the case view never mounts) and
            // there is nothing the caller can do besides retry. The
            // browser's error console surfaces it.
            let _ = window.location().assign(&href);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        info!(
            subject_id,
            "navigation::navigate_to_case called on native target (no-op)",
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    /// Native `navigate_to_case` must be callable without panicking
    /// — that is the contract test stubs depend on. The function
    /// returns `()`; we exercise it across a few input shapes.
    #[test]
    fn navigate_to_case_native_is_a_pure_function() {
        navigate_to_case("00000000-0000-0000-0000-000000000000");
        navigate_to_case("09d543ce-7291-40d1-b305-2dcdc1646c1a");
        // Empty string is not a valid SubjectId but the helper must
        // not panic — the route mismatch surfaces upstream.
        navigate_to_case("");
    }
}
