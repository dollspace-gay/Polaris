//! Thin `sessionStorage` shim.
//!
//! Issue #95 / mod-workstation feature #5 needs per-tab persistence for
//! the moderator exposure counter: a tab refresh must NOT reset the
//! accumulated count (the moderator just hit reload, the session is
//! still the same), but closing the tab MUST reset it (the moderator
//! has ended their shift, by definition the wellness counter is
//! per-session, not per-week-of-browser-restarts). That is exactly
//! what the browser's `window.sessionStorage` already gives us.
//!
//! `localStorage` is deliberately NOT used — wellness counters do not
//! persist past a real session boundary per TSPA guidance.
//!
//! # Targets
//!
//! Each function has a wasm impl that reaches through `web_sys::Window`
//! and a native stub that returns `None` / is a no-op. Calling sites
//! treat `None` as "no persisted value, start fresh". The same source
//! file compiles on both wasm32-unknown-unknown and native targets
//! (cargo test, IDE check) without `#[cfg]` at the call site.

#[cfg(target_arch = "wasm32")]
mod imp {
    /// Read `key` from `window.sessionStorage`. Returns `None` when:
    ///
    /// - there is no `window` (e.g. during the brief pre-mount window),
    /// - `sessionStorage` is unavailable (private-browsing modes that
    ///   refuse to expose it, or a sandboxed iframe),
    /// - the key is absent.
    ///
    /// All error paths collapse to `None`; the calling code falls back
    /// to its default state. There is no panicking branch — the wellness
    /// counter degrades gracefully when persistence is unavailable.
    pub(crate) fn get_item(key: &str) -> Option<String> {
        let window = web_sys::window()?;
        let storage = window.session_storage().ok().flatten()?;
        storage.get_item(key).ok().flatten()
    }

    /// Write `value` to `window.sessionStorage` under `key`. Errors are
    /// swallowed silently — wellness counters degrade gracefully when
    /// the storage write fails (e.g. quota exceeded, private-browsing
    /// mode); the in-memory signal still drives the UI.
    pub(crate) fn set_item(key: &str, value: &str) {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Ok(Some(storage)) = window.session_storage() else {
            return;
        };
        let _ = storage.set_item(key, value);
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    //! Native stubs. The pure-function unit tests in
    //! `exposure_counter::tests` exercise the state transitions
    //! directly, without going through persistence — these stubs
    //! exist so the call sites compile cleanly on native.

    pub(crate) fn get_item(_key: &str) -> Option<String> {
        None
    }

    pub(crate) fn set_item(_key: &str, _value: &str) {
        // Intentionally empty: native builds have no browser session.
    }
}

/// Read the value associated with `key` from `sessionStorage`.
///
/// See [`imp::get_item`] for the contract.
#[must_use]
pub fn get_item(key: &str) -> Option<String> {
    imp::get_item(key)
}

/// Write `value` under `key` to `sessionStorage`. Errors are swallowed.
///
/// See [`imp::set_item`] for the contract.
pub fn set_item(key: &str, value: &str) {
    imp::set_item(key, value);
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn native_get_item_returns_none() {
        // Native builds have no real browser sessionStorage; the stub
        // returns None so callers fall back to their default state.
        assert!(get_item("polaris.exposure-counter.test").is_none());
    }

    #[test]
    fn native_set_item_is_a_no_op() {
        // No panic, no observable side effect.
        set_item("polaris.exposure-counter.test", "{}");
    }
}
