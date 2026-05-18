//! Categorical published-default classification for a single label
//! value (issue #96 / mod-workstation feature #6).
//!
//! # Why this is not a probability distribution
//!
//! The case-view composer used to render a three-bucket "subscriber
//! forecast" (`hide / warn / ignore`) computed from AT-Proto-reference-
//! defaults heuristics. Those percentages were fabrications: the
//! AppView's `app.bsky.labeler.getServices` does NOT expose
//! per-subscriber preference telemetry, so any "85% hide / 12% warn"
//! line was just the operator's own published default dressed up as
//! a prediction. We removed it.
//!
//! What we have instead is the labeler's own categorical published
//! intent — the `severity` × `defaultSetting` of the
//! `app.bsky.labeler.service` record. That IS real signal: it tells
//! the moderator what subscribers who keep the default settings will
//! see. Subscribers who have overridden the default may render the
//! label differently; the AppView does not give us per-subscriber
//! visibility, and we no longer pretend it does.

/// The three categorical rendering outcomes a label can produce on a
/// subscriber's client.
///
/// Mirrors the AT-Proto `LabelValueDefinition.defaultSetting` field's
/// vocabulary verbatim — `hide`, `warn`, `ignore` — with an `Unknown`
/// variant for labels whose declaration is malformed or missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PublishedRendering {
    /// Subscribers using default settings will not see the labelled
    /// content at all (it is hidden behind the labeler's policy).
    Hide,
    /// Subscribers will see the labelled content behind a warning
    /// interstitial that they can click through.
    Warn,
    /// Subscribers will see the labelled content without any
    /// modification — this is the "label exists but renders
    /// passively" outcome.
    Ignore,
    /// The label's declaration is missing or carries an
    /// unrecognised `defaultSetting`; we cannot honestly say what
    /// subscribers will see.
    Unknown,
}

impl PublishedRendering {
    /// Short human-readable label rendered in the composer preview.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hide => "hide",
            Self::Warn => "warn",
            Self::Ignore => "ignore",
            Self::Unknown => "unknown",
        }
    }

    /// One-sentence description of the subscriber-side effect.
    /// Surfaced verbatim in the composer preview so the moderator
    /// always reads exactly what subscribers will see.
    #[must_use]
    pub const fn description(self) -> &'static str {
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
/// `default_setting` is the lowercase token from the labeler service
/// record's `LabelValueDefinition.defaultSetting` field. Unknown
/// values fall through to [`PublishedRendering::Unknown`] — we do not
/// invent a default; the moderator sees the honest "undefined" state.
#[must_use]
pub fn classify_published_rendering(default_setting: &str) -> PublishedRendering {
    match default_setting {
        "hide" => PublishedRendering::Hide,
        "warn" => PublishedRendering::Warn,
        "ignore" => PublishedRendering::Ignore,
        _ => PublishedRendering::Unknown,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic per rust-quality §7"
)]
mod tests {
    use super::*;

    #[test]
    fn classify_hide_default_is_hide() {
        assert_eq!(
            classify_published_rendering("hide"),
            PublishedRendering::Hide
        );
    }

    #[test]
    fn classify_warn_default_is_warn() {
        assert_eq!(
            classify_published_rendering("warn"),
            PublishedRendering::Warn
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
    fn classify_unknown_default_does_not_invent_a_value() {
        // The point of the change: do NOT fall back to a plausible
        // value that lies about the data. Unknown is unknown.
        assert_eq!(
            classify_published_rendering("not-a-real-setting"),
            PublishedRendering::Unknown,
        );
        assert_eq!(
            classify_published_rendering(""),
            PublishedRendering::Unknown,
        );
    }

    #[test]
    fn descriptions_never_empty() {
        for r in [
            PublishedRendering::Hide,
            PublishedRendering::Warn,
            PublishedRendering::Ignore,
            PublishedRendering::Unknown,
        ] {
            assert!(
                !r.description().is_empty(),
                "description for {r:?} is empty"
            );
            assert!(!r.label().is_empty(), "label for {r:?} is empty");
        }
    }

    #[test]
    fn descriptions_do_not_use_percentage_language() {
        // Regression guard: the OLD code fabricated "85% of
        // subscribers..." percentages. The NEW code is categorical
        // and honest — no percentage phrasing.
        for r in [
            PublishedRendering::Hide,
            PublishedRendering::Warn,
            PublishedRendering::Ignore,
            PublishedRendering::Unknown,
        ] {
            let desc = r.description();
            assert!(
                !desc.contains('%'),
                "{r:?} description contains percent sign: {desc}"
            );
            assert!(
                !desc.contains("estimate"),
                "{r:?} description uses estimate language: {desc}"
            );
            assert!(
                !desc.contains("approximately"),
                "{r:?} description uses approximation language: {desc}"
            );
        }
    }
}
