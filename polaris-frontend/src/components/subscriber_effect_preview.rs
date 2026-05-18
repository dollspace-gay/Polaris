//! Subscriber-effect preview — categorical published-rendering display.
//!
//! Inline preview rendered inside [`crate::components::action_composer::ActionComposer`]
//! while the moderator is composing a Label action. Shows the
//! labeler's PUBLISHED categorical intent for the in-progress label
//! value (`hide` / `warn` / `ignore`) plus the AT-Proto subscriber
//! count from `app.bsky.labeler.getServices.likeCount`.
//!
//! # What this is NOT
//!
//! Earlier revisions rendered a three-bucket percentage bar
//! (`85% hide / 12% warn / 3% ignore`) derived from AT-Proto
//! reference defaults. Those percentages were fabrications — the
//! AppView does not expose per-subscriber preference telemetry, so
//! any percentage was an editorial guess at how a representative
//! subscriber base interprets each `defaultSetting`. We removed the
//! bar.
//!
//! What we display now is exclusively real signal:
//! 1. The labeler's published `defaultSetting` — what subscribers
//!    using default settings will see (a categorical outcome, not a
//!    probability).
//! 2. The AppView's `likeCount` for the labeler — the actual
//!    subscriber count, when retrievable.
//!
//! # Data sources
//!
//! 1. `GET /api/labeler/policies` returns the operator's published
//!    `LabelerPolicies` shape (label values + per-value
//!    definitions) plus a TTL-cached `subscriber_likes` from
//!    `app.bsky.labeler.getServices.likeCount`. Fetched once on
//!    mount and cached in a Leptos signal.
//! 2. When the matching `LabelValueDefinition` is missing (the
//!    operator types a value not in their declared set), the
//!    preview renders an inline warning prompting them to update
//!    the wizard.
//!
//! The component is read-only — the affordance is informational.

#![allow(
    clippy::must_use_candidate,
    reason = "Leptos #[component] attribute strips outer derives; consumers always feed the return value into view!"
)]

use leptos::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::api_client::dto::LabelerPoliciesResponse;

/// The three categorical published-rendering outcomes a label can
/// produce on a subscriber's client.
///
/// Mirrors `polaris_backend::api::labeler_policies::forecast::PublishedRendering`
/// — the categorical replacement for the probability-bar fabrication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishedRendering {
    /// Subscribers using default settings will not see the content.
    Hide,
    /// Subscribers will see the content behind a warning
    /// interstitial they can click through.
    Warn,
    /// Subscribers will see the content unmodified.
    Ignore,
    /// `defaultSetting` is missing or unrecognised — the published
    /// rendering is undefined and we display that honestly.
    Unknown,
}

impl PublishedRendering {
    /// Short label rendered as the badge text.
    pub fn badge(self) -> &'static str {
        match self {
            Self::Hide => "HIDE",
            Self::Warn => "WARN",
            Self::Ignore => "IGNORE",
            Self::Unknown => "UNDEFINED",
        }
    }

    /// BEM modifier for the badge so the style can color-code the
    /// outcome (color is supplementary; the badge text carries the
    /// signal per design.md §7).
    pub fn modifier(self) -> &'static str {
        match self {
            Self::Hide => "subscriber-effect-preview__badge--hide",
            Self::Warn => "subscriber-effect-preview__badge--warn",
            Self::Ignore => "subscriber-effect-preview__badge--ignore",
            Self::Unknown => "subscriber-effect-preview__badge--unknown",
        }
    }

    /// One-sentence description of the subscriber-side effect.
    pub fn description(self) -> &'static str {
        match self {
            Self::Hide => "Subscribers using default settings will not see this content.",
            Self::Warn => {
                "Subscribers using default settings will see this content behind \
                 a warning interstitial they can click through."
            }
            Self::Ignore => {
                "Subscribers using default settings will see this content \
                 unmodified — the label is informational only."
            }
            Self::Unknown => {
                "The label's declared `defaultSetting` is missing or \
                 unrecognised; the published rendering is undefined."
            }
        }
    }
}

/// Classify a label's `defaultSetting` into a [`PublishedRendering`].
///
/// Unknown values become [`PublishedRendering::Unknown`] — we do NOT
/// fall back to a plausible default that lies about the data.
#[must_use]
pub fn classify_published_rendering(default_setting: &str) -> PublishedRendering {
    match default_setting {
        "hide" => PublishedRendering::Hide,
        "warn" => PublishedRendering::Warn,
        "ignore" => PublishedRendering::Ignore,
        _ => PublishedRendering::Unknown,
    }
}

/// Find the matching `LabelValueDefinition` for the given value in
/// the policy's `label_value_definitions` array.
///
/// Returns `None` when the value is not declared by the labeler.
/// Each declared entry returns the `defaultSetting` + `severity`
/// strings verbatim — no fallback synthesis. When a field is
/// missing, the corresponding string is `None`-replaced with empty
/// (the caller's classifier maps empties to
/// [`PublishedRendering::Unknown`]).
#[must_use]
pub fn lookup_definition(
    definitions: &serde_json::Value,
    label_value: &str,
) -> Option<(String, String)> {
    let arr = definitions.as_array()?;
    arr.iter().find_map(|entry| {
        let identifier = entry.get("identifier")?.as_str()?;
        if identifier == label_value {
            let default_setting = entry
                .get("defaultSetting")
                .or_else(|| entry.get("default_setting"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let severity = entry
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            Some((default_setting, severity))
        } else {
            None
        }
    })
}

/// Subscriber-effect preview. Renders inside [`crate::components::action_composer::ActionComposer`]
/// when the moderator is composing a Label action and has typed a
/// value.
#[component]
pub fn SubscriberEffectPreview(
    /// The in-progress label value the moderator is typing.
    #[prop(into)]
    label_value: Signal<String>,
    /// Whether the preview should render. False when the action kind
    /// is not Label, or when the label_value is empty.
    #[prop(into)]
    visible: Signal<bool>,
) -> impl IntoView {
    #[cfg(target_arch = "wasm32")]
    {
        render_wasm(label_value, visible)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = label_value;
        let _ = visible;
        render_native_stub()
    }
}

/// Native stub — returns an empty hidden span so the component
/// composes cleanly inside `ActionComposer` on the native build.
/// The wasm path is the operationally-meaningful render.
#[cfg(not(target_arch = "wasm32"))]
fn render_native_stub() -> AnyView {
    view! { <span class="subscriber-effect-preview__native-stub" hidden="true"></span> }.into_any()
}

/// Fetch state machine for the labeler-policy lookup. Wasm-only —
/// the variants are constructed inside [`render_wasm`] below, and
/// the type itself is only used by [`render_state`] which is also
/// wasm-only.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
enum PolicyState {
    Loading,
    Ready(LabelerPoliciesResponse),
    Failed(String),
}

/// wasm-only render: drives the labeler-policy fetch + dispatches
/// on the resulting [`PolicyState`].
#[cfg(target_arch = "wasm32")]
fn render_wasm(label_value: Signal<String>, visible: Signal<bool>) -> AnyView {
    use crate::api_client::{PolarisApiClient as _, default_client};

    let (policy_state, set_policy_state) = signal(PolicyState::Loading);
    leptos::task::spawn_local(async move {
        match default_client("") {
            Ok(client) => match client.labeler_policies().await {
                Ok(p) => set_policy_state.set(PolicyState::Ready(p)),
                Err(e) => set_policy_state.set(PolicyState::Failed(e.to_string())),
            },
            Err(e) => set_policy_state.set(PolicyState::Failed(e.to_string())),
        }
    });

    view! {
        <Show when=move || visible.get() fallback=|| view! { <></> }>
            <section class="subscriber-effect-preview" aria-live="polite">
                {move || render_state(policy_state.get(), label_value.get())}
            </section>
        </Show>
    }
    .into_any()
}

#[cfg(target_arch = "wasm32")]
fn render_state(state: PolicyState, label_value: String) -> AnyView {
    match state {
        PolicyState::Loading => view! {
            <p class="subscriber-effect-preview__loading">
                "Loading labeler policy..."
            </p>
        }
        .into_any(),
        PolicyState::Ready(policy) => render_for_policy(policy, label_value).into_any(),
        PolicyState::Failed(msg) => render_error(&msg).into_any(),
    }
}

/// Render the categorical published-rendering display for a label
/// value, plus the truthful subscriber count.
#[cfg(target_arch = "wasm32")]
#[allow(
    clippy::needless_pass_by_value,
    reason = "policy + label_value are moved into the returned view! tree"
)]
fn render_for_policy(policy: LabelerPoliciesResponse, label_value: String) -> impl IntoView {
    let trimmed = label_value.trim().to_owned();
    if trimmed.is_empty() {
        return view! {
            <p class="subscriber-effect-preview__hint">
                "Type a label value to preview the published rendering."
            </p>
        }
        .into_any();
    }
    let Some((default_setting, severity)) =
        lookup_definition(&policy.label_value_definitions, &trimmed)
    else {
        return view! {
            <p class="subscriber-effect-preview__not-declared" role="alert">
                "This label value is not in your declared "
                <code>"labelValueDefinitions"</code>". Consumers will not "
                "render it as expected. Update the declaration via the setup wizard."
            </p>
        }
        .into_any();
    };

    let rendering = classify_published_rendering(&default_setting);
    let badge_text = rendering.badge();
    let badge_modifier = rendering.modifier();
    let description = rendering.description();
    let subscriber_line = subscriber_count_line(policy.subscriber_likes);
    let severity_display = if severity.is_empty() {
        "undeclared".to_owned()
    } else {
        severity
    };
    let default_display = if default_setting.is_empty() {
        "undeclared".to_owned()
    } else {
        default_setting
    };

    view! {
        <p class="subscriber-effect-preview__heading">
            "Published rendering for "
            <code>{trimmed}</code>
            " (severity: "{severity_display}", default: "{default_display}")"
        </p>
        <p class=move || format!("subscriber-effect-preview__badge {badge_modifier}")
           aria-label=format!("Published default rendering: {badge_text}")>
            {badge_text}
        </p>
        <p class="subscriber-effect-preview__description">
            {description}
        </p>
        <p class="subscriber-effect-preview__subscriber-count">
            {subscriber_line}
        </p>
        <p class="subscriber-effect-preview__disclaimer">
            "Per-subscriber rendering may differ when a subscriber has overridden \
             the default. The AppView does not expose per-subscriber preference \
             telemetry; this preview shows the labeler's published intent only."
        </p>
    }
    .into_any()
}

/// Render an inline error when the policy fetch fails.
#[cfg(target_arch = "wasm32")]
fn render_error(message: &str) -> impl IntoView {
    let msg = format!(
        "Could not load labeler policy ({message}). Published-rendering preview \
         unavailable; the submission still works."
    );
    view! {
        <p class="subscriber-effect-preview__error" role="alert">{msg}</p>
    }
}

/// Render the subscriber-count line honestly: real count when known,
/// "no subscribers yet" when the labeler is published-but-empty,
/// "unknown" when the AppView did not provide a count.
///
/// `pub` so the dead-code lint exempts it on the native target where
/// the only non-test caller (`render_for_policy`) is cfg-gated to
/// wasm; the function is part of this module's tested public surface.
#[must_use]
pub fn subscriber_count_line(subscriber_likes: Option<u32>) -> String {
    match subscriber_likes {
        Some(0) => "Subscriber count: 0. The labeler is published but has no subscribers \
             yet — no real-world rendering data is available."
            .to_owned(),
        Some(1) => "Subscriber count: 1 (AT-Proto `getServices.likeCount`).".to_owned(),
        Some(n) => format!("Subscriber count: {n} (AT-Proto `getServices.likeCount`).",),
        None => "Subscriber count: unknown. The operator has not yet published a labeler \
             record, OR the AppView fetch failed — no count is available."
            .to_owned(),
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

    // ── classify_published_rendering ────────────────────────────────

    #[test]
    fn classify_hide_default_is_hide() {
        assert_eq!(
            classify_published_rendering("hide"),
            PublishedRendering::Hide,
        );
    }

    #[test]
    fn classify_warn_default_is_warn() {
        assert_eq!(
            classify_published_rendering("warn"),
            PublishedRendering::Warn,
        );
    }

    #[test]
    fn classify_ignore_default_is_ignore() {
        assert_eq!(
            classify_published_rendering("ignore"),
            PublishedRendering::Ignore,
        );
    }

    #[test]
    fn classify_unknown_does_not_invent_a_value() {
        // Regression guard: the OLD `compute_distribution` fell back
        // to a synthesised "warn" row for unknown default-settings,
        // which is the kind of fake-data fallback the user told us
        // to remove. The new classifier MUST surface unknown as
        // unknown.
        assert_eq!(
            classify_published_rendering("not-a-real-setting"),
            PublishedRendering::Unknown,
        );
        assert_eq!(
            classify_published_rendering(""),
            PublishedRendering::Unknown
        );
    }

    // ── lookup_definition ───────────────────────────────────────────

    #[test]
    fn lookup_definition_returns_declared_pair() {
        let defs = serde_json::json!([
            { "identifier": "spam", "defaultSetting": "warn", "severity": "alert" },
        ]);
        let (default_setting, severity) =
            lookup_definition(&defs, "spam").expect("spam is declared");
        assert_eq!(default_setting, "warn");
        assert_eq!(severity, "alert");
    }

    #[test]
    fn lookup_definition_missing_label_returns_none() {
        let defs = serde_json::json!([
            { "identifier": "spam", "defaultSetting": "warn", "severity": "alert" },
        ]);
        assert!(lookup_definition(&defs, "porn").is_none());
    }

    #[test]
    fn lookup_definition_returns_empty_for_missing_fields_not_fake_defaults() {
        // Old code fell back to "warn"/"inform" when fields were
        // missing — fake-data fallback. New code returns empty
        // strings; classifier maps to Unknown.
        let defs = serde_json::json!([
            { "identifier": "spam" },
        ]);
        let (default_setting, severity) = lookup_definition(&defs, "spam").unwrap();
        assert!(default_setting.is_empty(), "got {default_setting:?}");
        assert!(severity.is_empty(), "got {severity:?}");
        assert_eq!(
            classify_published_rendering(&default_setting),
            PublishedRendering::Unknown,
        );
    }

    // ── subscriber_count_line ───────────────────────────────────────

    #[test]
    fn subscriber_count_line_zero_says_no_subscribers_yet() {
        let line = subscriber_count_line(Some(0));
        assert!(line.contains('0'));
        assert!(line.contains("no subscribers yet"));
        // Must NOT claim there is no telemetry wired — we DO have a
        // count, it's just zero.
        assert!(!line.contains("not yet wired"));
    }

    #[test]
    fn subscriber_count_line_one_uses_singular() {
        let line = subscriber_count_line(Some(1));
        assert!(line.contains("Subscriber count: 1"));
    }

    #[test]
    fn subscriber_count_line_many_uses_plural() {
        let line = subscriber_count_line(Some(42));
        assert!(line.contains("Subscriber count: 42"));
    }

    #[test]
    fn subscriber_count_line_none_says_unknown_not_fake_value() {
        let line = subscriber_count_line(None);
        assert!(line.contains("unknown"));
        // Must not display a fake "0" or "1" for an unknown count.
        assert!(!line.contains("Subscriber count: 0"));
    }

    // ── No-fake-data regression guards ──────────────────────────────

    #[test]
    fn no_percentage_phrasing_in_any_output_path() {
        // Sweep across all rendering descriptions and subscriber
        // lines. None of them may contain percent-sign phrasing —
        // that's the load-bearing test for the user's "no fake
        // percentages" directive.
        for r in [
            PublishedRendering::Hide,
            PublishedRendering::Warn,
            PublishedRendering::Ignore,
            PublishedRendering::Unknown,
        ] {
            let desc = r.description();
            assert!(!desc.contains('%'), "{r:?} description: {desc}");
            assert!(
                !desc.to_lowercase().contains("estimate"),
                "{r:?} description: {desc}",
            );
        }
        for count in [None, Some(0_u32), Some(1), Some(100), Some(50_000)] {
            let line = subscriber_count_line(count);
            assert!(!line.contains('%'), "subscriber line: {line}");
            assert!(
                !line.to_lowercase().contains("estimate"),
                "subscriber line: {line}",
            );
        }
    }
}
