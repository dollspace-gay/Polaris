//! `ExposureCounter` — per-session moderator wellness counter
//! (issue #95 / mod-workstation feature #5).
//!
//! Models the TSPA "shift-cap" recommendation: after a configurable
//! number of sustained reveals of potentially-graphic content, surface
//! a non-blocking toast that nudges the moderator to take a 5-minute
//! break. The moderator's autonomy is non-negotiable — they can keep
//! working past the nudge.
//!
//! # Storage discipline
//!
//! The counter persists in `sessionStorage` (NOT `localStorage`) per
//! the design contract: a tab refresh preserves the accumulated
//! count, a tab close resets it. Wellness counters do not persist
//! past a real session boundary.
//!
//! # Privacy
//!
//! No exposure events are logged to the backend. The TSPA's wellness
//! curriculum is explicit that aggregated-operator exposure reports
//! are an opt-in workstream; this counter is client-side only.

use chrono::{DateTime, Duration, Utc};
use leptos::ev;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

// ── Constants ───────────────────────────────────────────────────────────

/// Default exposure threshold, in reveals. Per TSPA's wellness
/// curriculum: roughly one shift's worth of graphic content before a
/// break is actively prompted.
pub const DEFAULT_THRESHOLD: u32 = 20;

/// `sessionStorage` key for the serialised [`ExposureState`].
pub const STORAGE_KEY: &str = "polaris.exposure-counter.v1";

/// Cooldown window between consecutive nag toasts. After a dismiss,
/// the toast must NOT re-fire until either (a) the moderator hits the
/// threshold again with a fresh batch of reveals, or (b) at least
/// this much wall-clock time has elapsed since the dismiss.
///
/// 60 seconds is short enough that a moderator who genuinely wants
/// the nudge gone for a session-long stretch will simply keep
/// dismissing; it is long enough that the nudge does not become
/// chatter immediately after a dismiss.
pub const NAG_COOLDOWN_SECONDS: i64 = 60;

// ── State type ──────────────────────────────────────────────────────────

/// Persisted per-session exposure state.
///
/// Held inside a Leptos `RwSignal<ExposureState>` mounted in the app
/// root; serialised into `sessionStorage` under [`STORAGE_KEY`] on
/// every mutation so a tab refresh preserves the counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureState {
    /// Cumulative count of `MediaPreview` reveals this session.
    pub revealed_count: u32,
    /// Cumulative count of action submissions on subjects that had
    /// at least one media artifact attached.
    pub actions_submitted: u32,
    /// Timestamp of the last nag-toast dismissal (either path). The
    /// nag's `show / hide` predicate uses this to enforce the
    /// cooldown window.
    pub nag_dismissed_at: Option<DateTime<Utc>>,
    /// Configurable threshold. Defaults to [`DEFAULT_THRESHOLD`].
    pub threshold: u32,
}

impl Default for ExposureState {
    fn default() -> Self {
        Self {
            revealed_count: 0,
            actions_submitted: 0,
            nag_dismissed_at: None,
            threshold: DEFAULT_THRESHOLD,
        }
    }
}

// ── Pure helpers (native-testable) ──────────────────────────────────────

/// Decide whether the nag toast should be visible.
///
/// Returns `true` when **both** conditions hold:
///
/// 1. `revealed_count >= threshold`, AND
/// 2. `nag_dismissed_at` is either `None` OR sufficiently old (more
///    than [`NAG_COOLDOWN_SECONDS`] ago relative to `now`).
///
/// Pulled out as a free function so the unit tests can drive every
/// branch deterministically by injecting `now`.
#[must_use]
pub fn should_show_nag(state: &ExposureState, now: DateTime<Utc>) -> bool {
    if state.revealed_count < state.threshold {
        return false;
    }
    match state.nag_dismissed_at {
        None => true,
        Some(dismissed_at) => {
            let cutoff = dismissed_at + Duration::seconds(NAG_COOLDOWN_SECONDS);
            now >= cutoff && state.revealed_count >= state.threshold.saturating_mul(2)
        }
    }
}

/// Increment `revealed_count` by one with saturating semantics so a
/// pathological session that exceeds `u32::MAX` (impossible in
/// practice but mechanically possible) does not wrap.
pub fn record_reveal(state: &mut ExposureState) {
    state.revealed_count = state.revealed_count.saturating_add(1);
}

/// Increment `actions_submitted` **only** when the subject the
/// moderator just submitted against had media attached. The
/// `subject_has_media` flag is supplied by the caller (the
/// `ActionComposer` integration point) so this function is purely
/// declarative on state.
pub fn record_action(state: &mut ExposureState, subject_has_media: bool) {
    if subject_has_media {
        state.actions_submitted = state.actions_submitted.saturating_add(1);
    }
}

/// Mark the nag as dismissed at `now`. Used by both dismiss paths
/// ("Take a break" and "Continue") — the only client-side difference
/// is a `tracing::info!` ping for UX research signal, recorded at the
/// call site.
pub fn dismiss_nag(state: &mut ExposureState, now: DateTime<Utc>) {
    state.nag_dismissed_at = Some(now);
}

// ── Context handle ──────────────────────────────────────────────────────

/// Newtype wrapper around the global exposure signal handle.
///
/// Held in Leptos context so other components ([`MediaPreview`],
/// `ActionComposer`) can reach the counter without prop drilling.
/// `RwSignal` is `Copy` on Leptos 0.8, so cloning the wrapper is
/// cheap.
#[derive(Debug, Clone, Copy)]
pub struct ExposureSignal(pub RwSignal<ExposureState>);

/// Read the current exposure signal off context, if mounted.
///
/// Returns `None` when called from a component tree that has not
/// mounted [`ExposureCounter`] — for example, an isolated test
/// rendering a single child component. Callers that need to record a
/// reveal / action treat `None` as "no global counter, no-op".
#[must_use]
pub fn current_exposure_signal() -> Option<RwSignal<ExposureState>> {
    use_context::<ExposureSignal>().map(|h| h.0)
}

/// Record an action submission against `subject_has_media` on the
/// global exposure signal, if one is mounted.
///
/// Used by `action_composer::ActionComposer` on the success branch of
/// its submit handler.
pub fn record_action_on_global(subject_has_media: bool) {
    if let Some(signal) = current_exposure_signal() {
        signal.update(|s| record_action(s, subject_has_media));
    }
}

// ── Wall-clock injection ────────────────────────────────────────────────

/// Read the current UTC instant. Indirection so the nag-toast effect
/// stays testable without freezing `chrono::Utc::now` globally — the
/// pure-function tests construct their own `DateTime<Utc>` values.
fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

// ── Component ───────────────────────────────────────────────────────────

/// Global exposure-counter mount point.
///
/// Mount once at the top of the [`crate::app::App`] tree (next to
/// [`crate::components::command_palette::CommandPalette`]) so the nag
/// toast is reachable from every page. The component:
///
/// 1. Hydrates the [`ExposureState`] from `sessionStorage` on mount
///    (falling back to default if absent / corrupt).
/// 2. Provides the [`ExposureSignal`] handle to Leptos context.
/// 3. Persists every mutation back to `sessionStorage`.
/// 4. Renders a non-blocking toast at the bottom of the viewport
///    when [`should_show_nag`] returns true.
#[allow(
    clippy::must_use_candidate,
    reason = "#[component] discards outer attributes; Leptos always consumes the return value"
)]
#[component]
pub fn ExposureCounter() -> impl IntoView {
    // Hydrate the signal from sessionStorage. A corrupt blob falls
    // back to default — there is no panicking branch on the wasm
    // path, per the issue #95 forbidden-pattern checklist.
    let initial = crate::session_storage::get_item(STORAGE_KEY)
        .as_deref()
        .and_then(|raw| serde_json::from_str::<ExposureState>(raw).ok())
        .unwrap_or_default();

    let signal = RwSignal::new(initial);

    // Provide the handle on Leptos context BEFORE setting up the
    // persistence effect so child components mounting concurrently
    // can immediately reach the signal.
    provide_context(ExposureSignal(signal));

    // Persist on every mutation. The effect's read-cycle subscribes
    // to the signal; the body serialises and writes to storage. A
    // serialisation failure is silently ignored — wellness counters
    // degrade gracefully (the in-memory signal continues to drive
    // the UI even when persistence is unavailable).
    Effect::new(move |_| {
        let snapshot = signal.get();
        if let Ok(serialised) = serde_json::to_string(&snapshot) {
            crate::session_storage::set_item(STORAGE_KEY, &serialised);
        }
    });

    // Reactive accessor for the nag predicate. `now_utc()` is called
    // fresh on every reactive read; combined with the threshold +
    // dismiss-timestamp inputs, the toast appears + disappears
    // without a separate timer.
    let show_nag = move || should_show_nag(&signal.get(), now_utc());

    // Dismiss handlers — both record the same timestamp; the
    // difference is a tracing ping for UX research.
    let on_take_break = move |_ev: ev::MouseEvent| {
        let when = now_utc();
        signal.update(|s| dismiss_nag(s, when));
        tracing::info!(
            target = "polaris_frontend::exposure_counter",
            dismiss_path = "take-break",
            "moderator dismissed exposure nag via take-break path"
        );
    };

    let on_continue = move |_ev: ev::MouseEvent| {
        let when = now_utc();
        signal.update(|s| dismiss_nag(s, when));
        tracing::info!(
            target = "polaris_frontend::exposure_counter",
            dismiss_path = "continue",
            "moderator dismissed exposure nag via continue path"
        );
    };

    view! {
        <Show
            when=show_nag
            fallback=|| view! { <></> }
        >
            <aside
                class="exposure-counter exposure-counter--visible"
                role="status"
                aria-live="polite"
                aria-label="Wellness reminder"
            >
                <p class="exposure-counter__message">
                    "You've reviewed "
                    <strong class="exposure-counter__count">
                        {move || signal.with(|s| s.revealed_count.to_string())}
                    </strong>
                    " pieces of media this session. "
                    "Consider taking a 5-minute break — content moderation work "
                    "has cumulative emotional impact."
                </p>
                <div class="exposure-counter__actions">
                    <button
                        type="button"
                        class="exposure-counter__action exposure-counter__action--break"
                        on:click=on_take_break
                    >
                        "Take a break"
                    </button>
                    <button
                        type="button"
                        class="exposure-counter__action exposure-counter__action--continue"
                        on:click=on_continue
                    >
                        "Continue"
                    </button>
                </div>
            </aside>
        </Show>
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    fn epoch() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("fixed UTC instant")
    }

    // ── should_show_nag: every named branch ───────────────────────

    #[test]
    fn nag_hidden_under_threshold() {
        let state = ExposureState {
            revealed_count: 5,
            ..ExposureState::default()
        };
        assert!(!should_show_nag(&state, epoch()));
    }

    #[test]
    fn nag_shown_exactly_at_threshold_with_no_prior_dismiss() {
        let state = ExposureState {
            revealed_count: DEFAULT_THRESHOLD,
            ..ExposureState::default()
        };
        assert!(should_show_nag(&state, epoch()));
    }

    #[test]
    fn nag_hidden_during_cooldown_after_dismiss() {
        let now = epoch();
        let state = ExposureState {
            revealed_count: DEFAULT_THRESHOLD,
            // Dismiss 30s ago — under the 60s cooldown.
            nag_dismissed_at: Some(now - Duration::seconds(30)),
            ..ExposureState::default()
        };
        assert!(
            !should_show_nag(&state, now),
            "nag must stay hidden during the post-dismiss cooldown window"
        );
    }

    #[test]
    fn nag_retriggers_after_second_threshold_post_dismiss() {
        let now = epoch();
        let state = ExposureState {
            // 40 reveals — twice the default threshold.
            revealed_count: DEFAULT_THRESHOLD.saturating_mul(2),
            threshold: DEFAULT_THRESHOLD,
            // Dismiss is well past the cooldown.
            nag_dismissed_at: Some(now - Duration::seconds(NAG_COOLDOWN_SECONDS + 60)),
            ..ExposureState::default()
        };
        assert!(
            should_show_nag(&state, now),
            "nag must re-fire after another threshold worth of reveals"
        );
    }

    #[test]
    fn nag_hidden_when_under_second_threshold_after_dismiss() {
        let now = epoch();
        let state = ExposureState {
            // 25 reveals — over the first threshold, under the second.
            revealed_count: DEFAULT_THRESHOLD + 5,
            threshold: DEFAULT_THRESHOLD,
            // Cooldown elapsed.
            nag_dismissed_at: Some(now - Duration::seconds(NAG_COOLDOWN_SECONDS + 60)),
            ..ExposureState::default()
        };
        assert!(
            !should_show_nag(&state, now),
            "nag must stay hidden until the SECOND threshold after a dismiss"
        );
    }

    // ── record_reveal ─────────────────────────────────────────────

    #[test]
    fn record_reveal_increments_and_clamps_at_u32_max() {
        let mut state = ExposureState::default();
        record_reveal(&mut state);
        assert_eq!(state.revealed_count, 1);

        // Saturating semantics — bump to MAX, then once more.
        state.revealed_count = u32::MAX - 1;
        record_reveal(&mut state);
        assert_eq!(state.revealed_count, u32::MAX);
        record_reveal(&mut state);
        assert_eq!(state.revealed_count, u32::MAX, "must saturate, not wrap");
    }

    // ── record_action ─────────────────────────────────────────────

    #[test]
    fn record_action_increments_only_for_media_bearing_subjects() {
        let mut state = ExposureState::default();
        record_action(&mut state, false);
        assert_eq!(
            state.actions_submitted, 0,
            "no-media action must NOT increment the counter"
        );
        record_action(&mut state, true);
        assert_eq!(state.actions_submitted, 1);
        record_action(&mut state, true);
        assert_eq!(state.actions_submitted, 2);
    }

    // ── threshold-boundary edge cases ─────────────────────────────

    #[test]
    fn threshold_boundary_just_below_and_just_at() {
        let mut state = ExposureState {
            threshold: 10,
            revealed_count: 9,
            ..ExposureState::default()
        };
        assert!(!should_show_nag(&state, epoch()));
        state.revealed_count = 10;
        assert!(should_show_nag(&state, epoch()));
    }

    // ── dismiss_nag ───────────────────────────────────────────────

    #[test]
    fn dismiss_nag_records_timestamp() {
        let when = epoch();
        let mut state = ExposureState::default();
        dismiss_nag(&mut state, when);
        assert_eq!(state.nag_dismissed_at, Some(when));
    }

    // ── ExposureState serde round-trip ────────────────────────────

    #[test]
    fn exposure_state_round_trips_through_serde() {
        let state = ExposureState {
            revealed_count: 7,
            actions_submitted: 3,
            nag_dismissed_at: Some(epoch()),
            threshold: 25,
        };
        let raw = serde_json::to_string(&state).expect("serialize");
        let back: ExposureState = serde_json::from_str(&raw).expect("deserialize");
        assert_eq!(back, state);
    }
}
