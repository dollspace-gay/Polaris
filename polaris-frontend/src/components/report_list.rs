//! `ReportList` — current reports against the subject, with the
//! per-reporter reputation context that issue #37 / design.md §9.3
//! produces, plus per-report quick-action affordances (Acknowledge /
//! Escalate) so a moderator can act on an inbound report without
//! scrolling to the action composer.
//!
//! # Layout (rewritten in #187)
//!
//! Each report is a compact stacked card:
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │ [category]  from <reporter>          [when]  │
//! │ "<body>"                                     │
//! │ [reputation chip]                            │
//! │ [Acknowledge] [Escalate]                     │
//! │ ─ action feedback ─                          │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! The prior version used a 3-column grid that overflowed when the
//! reason category or body contained long unbreakable strings (DIDs,
//! AT-URIs). The new layout is vertical-stacked with `overflow-wrap:
//! anywhere` on long-text fields so no single report can ever push
//! the panel past the case-view's main-column boundary.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use leptos::prelude::*;
use leptos::task::spawn_local;
use polaris_types::{ActionKind, IncidentId, PolicyId, Report, ReportId, SubjectId};

use crate::api_client::dto::{MuteReporterBody, ReporterContext, SubmitAction};
use crate::api_client::{ApiError, PolarisApiClient, default_client};

/// Default policy reference attached to quick-action submissions.
///
/// Matches the `action_composer`'s `DEFAULT_POLICY_REF`; the
/// backend's `policy::KNOWN_POLICY_REFS` allow-list accepts it. A
/// moderator who wants a different policy can use the
/// `ActionComposer` below instead.
const DEFAULT_POLICY_REF: &str = "polaris.spam";

/// How long an action stays operator-reversible. design.md §5.5
/// pins this at 24h.
const REVERSIBLE_WINDOW_HOURS: i64 = 24;

/// Reputation-band classifier. Each band carries a stable
/// human-readable label + a BEM modifier so the styling can flag
/// concerning reporters without conveying information by colour alone
/// (per design.md §7 — the text label is the primary signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReputationBand {
    /// First time Polaris has seen this DID file a report.
    BrandNew,
    /// Reporter has filed reports before but none have produced an
    /// action — the moderator should weight this report cautiously.
    Unproven,
    /// Reporter is well-calibrated — their reports tend to produce
    /// actions.
    Trusted,
    /// Reporter has filed reports that consistently do not produce
    /// actions — a possible weaponised-reporter signal.
    NoisyOrAdversarial,
}

impl ReputationBand {
    fn label(self) -> &'static str {
        match self {
            Self::BrandNew => "new reporter (never seen before)",
            Self::Unproven => "unproven reporter (no actioned reports yet)",
            Self::Trusted => "trusted reporter",
            Self::NoisyOrAdversarial => "low-signal reporter (many reports, few actioned)",
        }
    }

    fn modifier(self) -> &'static str {
        match self {
            Self::BrandNew => "report-list__reputation--new",
            Self::Unproven => "report-list__reputation--unproven",
            Self::Trusted => "report-list__reputation--trusted",
            Self::NoisyOrAdversarial => "report-list__reputation--noisy",
        }
    }
}

/// Classify a reporter context into a [`ReputationBand`].
fn classify(ctx: &ReporterContext) -> ReputationBand {
    if ctx.reports_filed == 0 {
        return ReputationBand::BrandNew;
    }
    if ctx.reports_actioned == 0 {
        return ReputationBand::Unproven;
    }
    if ctx.reputation_score >= 0.5 {
        return ReputationBand::Trusted;
    }
    ReputationBand::NoisyOrAdversarial
}

/// Per-row outcome of a quick-action click. `None` is the resting
/// state; `Pending` disables the buttons; `Success` / `Error` displays
/// a short feedback line below the action row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ActionOutcome {
    None,
    Pending,
    Success(String),
    Error(String),
}

/// Render the subject's current reports + reputation context, with
/// per-report quick actions.
///
/// # Props
///
/// - `reports`: the `reports` vector from the case view response.
/// - `reporter_contexts`: parallel `ReporterContext` rows keyed by
///   `reporter_did`. Brand-new reporters appear here with neutral
///   defaults (`reports_filed = 0`, score = 0).
/// - `subject_id`: the subject these reports target. Quick-action
///   POSTs go to `/api/cases/{subject_id}/actions`.
/// - `incident_id`: the case-view's current incident binding (the
///   page derives it from the last action in history). Required on
///   every `SubmitAction` payload.
///
/// # Accessibility
///
/// The container is `role="region" aria-label="Reports"`; each report
/// is a `<li>` inside a `<ul role="list">` so screen-reader
/// list-navigation shortcuts work as expected. The reputation chip
/// carries an `aria-label` so the band is announced together with the
/// report category, not only conveyed by colour.
// See `subject_header::SubjectHeader` for the lint-allow rationale.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn ReportList(
    /// Reports vector from the case-view DTO.
    reports: Vec<Report>,
    /// Per-reporter reputation context (one entry per distinct
    /// `reporter_did` in `reports`).
    reporter_contexts: Vec<ReporterContext>,
    /// Subject identifier for the action POST URL.
    subject_id: SubjectId,
    /// Incident binding for `SubmitAction.incident_id`.
    incident_id: IncidentId,
) -> impl IntoView {
    let count = reports.len();
    let lookup: HashMap<String, ReporterContext> = reporter_contexts
        .into_iter()
        .map(|c| (c.did.clone(), c))
        .collect();

    // Pre-pair each report with its owned reporter-context clone
    // BEFORE the iterator closure — the `view!` macro inside
    // `render_report_row` returns a closure-laden view that the
    // borrow checker can't prove ends within the iterator scope,
    // so any borrow into `lookup` escapes the iterator's lifetime.
    // Owning the row's `ReporterContext` per iteration avoids the
    // escape entirely.
    let rows = reports
        .into_iter()
        .map(|r| {
            let ctx = lookup
                .get(r.reporter_did.as_str())
                .cloned()
                .unwrap_or_else(|| ReporterContext {
                    did: r.reporter_did.to_string(),
                    reports_filed: 0,
                    reports_actioned: 0,
                    reputation_score: 0.0,
                    account_age_days: 0,
                });
            render_report_row(r, ctx, subject_id, incident_id)
        })
        .collect::<Vec<_>>();

    view! {
        <section class="report-list" role="region" aria-label="Reports">
            <h2>"Reports"</h2>
            {move || {
                if count == 0 {
                    view! {
                        <p class="report-list__empty" role="status">
                            "No active reports against this subject."
                        </p>
                    }.into_any()
                } else {
                    view! {
                        <p class="report-list__count" role="status">
                            {count}" report(s) consolidated under this case."
                        </p>
                    }.into_any()
                }
            }}
            <ul class="report-list__list" role="list">
                {rows}
            </ul>
        </section>
    }
}

/// Render one report row including the quick-action affordances.
#[allow(clippy::too_many_lines)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "`impl IntoView` return captures references unless inputs are owned; taking owned values keeps the closure boundaries clean"
)]
fn render_report_row(
    report: Report,
    ctx_row: ReporterContext,
    subject_id: SubjectId,
    incident_id: IncidentId,
) -> impl IntoView {
    let category = report.category.to_string();
    let category_for_buttons = category.clone();
    let reporter_did = report.reporter_did.to_string();
    let when = report.created_at.to_rfc3339();
    let body_text = report.body.clone();
    let body_empty = body_text.trim().is_empty();
    // Prefer the report row's OWN incident_id when the aggregator
    // has bound it. The case-view's `incident_id` prop is derived
    // from the subject's action history, which is empty for an
    // inbound-report-only subject and falls back to a fresh-random
    // UUID that does not match any incidents row — submitting a
    // SubmitAction with that bogus id would fail the FK and surface
    // as an opaque 500 ("non-functional click"). Honouring the
    // report's bound incident keeps the click reliable when the
    // aggregator has done its work, and falls back to the route
    // prop only when neither source has one.
    let effective_incident_id = report.incident_id.unwrap_or(incident_id);

    let band = classify(&ctx_row);
    let band_class = band.modifier();
    let band_label = band.label();
    let band_summary = match band {
        ReputationBand::BrandNew => {
            "no prior history with this DID — first report we've seen".to_owned()
        }
        ReputationBand::Unproven => format!(
            "{} report(s) filed, 0 actioned (no actioned history yet); age {}d",
            ctx_row.reports_filed, ctx_row.account_age_days,
        ),
        ReputationBand::Trusted | ReputationBand::NoisyOrAdversarial => format!(
            "{} reports filed, {} actioned, score {:.2}, age {}d",
            ctx_row.reports_filed,
            ctx_row.reports_actioned,
            ctx_row.reputation_score,
            ctx_row.account_age_days,
        ),
    };

    let outcome = RwSignal::new(ActionOutcome::None);

    // The per-report idempotency key passed through every report-card
    // submit (issue #202). With it set, the backend row-locks the
    // report row, returns the existing action on the second click
    // instead of inserting a duplicate, and filters the actioned row
    // out of the next case-view render. The `outcome::Pending` guard
    // below absorbs same-render double-clicks BEFORE the network round
    // trip even fires; the server-side dedupe is the deeper defense.
    let report_id = report.id;

    // Click handlers — each builds reasoning text from the report's
    // category and fires the matching submit_action POST (for the
    // three action-row verbs) or muted-reporters POST (for the
    // ignore-reporter affordance). The leading guard short-circuits
    // double-clicks while a request is in flight.
    let ack_category = category_for_buttons.clone();
    let on_ack = move |_| {
        if matches!(outcome.get_untracked(), ActionOutcome::Pending) {
            return;
        }
        outcome.set(ActionOutcome::Pending);
        let reasoning =
            format!("Acknowledged inbound report ({ack_category}) — under continued observation.",);
        spawn_action(
            subject_id,
            effective_incident_id,
            ActionKind::NoAction,
            reasoning,
            Some(report_id),
            outcome,
        );
    };

    let dismiss_category = category_for_buttons.clone();
    let on_dismiss = move |_| {
        if matches!(outcome.get_untracked(), ActionOutcome::Pending) {
            return;
        }
        outcome.set(ActionOutcome::Pending);
        let reasoning =
            format!("Dismissed inbound report ({dismiss_category}) — not a policy violation.",);
        spawn_action(
            subject_id,
            effective_incident_id,
            ActionKind::NoAction,
            reasoning,
            Some(report_id),
            outcome,
        );
    };

    let esc_category = category_for_buttons;
    let on_escalate = move |_| {
        if matches!(outcome.get_untracked(), ActionOutcome::Pending) {
            return;
        }
        outcome.set(ActionOutcome::Pending);
        let reasoning = format!("Escalated for senior review on inbound report ({esc_category}).",);
        spawn_action(
            subject_id,
            effective_incident_id,
            ActionKind::Escalate,
            reasoning,
            Some(report_id),
            outcome,
        );
    };

    let reporter_for_mute = reporter_did.clone();
    let on_mute_reporter = move |_| {
        if matches!(outcome.get_untracked(), ActionOutcome::Pending) {
            return;
        }
        outcome.set(ActionOutcome::Pending);
        let did = reporter_for_mute.clone();
        spawn_mute_reporter(did, outcome);
    };

    let outcome_for_buttons = outcome;
    let outcome_for_feedback = outcome;
    let reporter_display = reporter_did.clone();
    let reporter_for_attr = reporter_did.clone();

    view! {
        <li class="report-list__item">
            <div class="report-list__meta">
                <span class="report-list__category">{category}</span>
                <time class="report-list__when">{when}</time>
            </div>
            <p class="report-list__reporter-line">
                <span class="report-list__reporter-label">"Reporter:"</span>
                <code
                    class="report-list__reporter-did"
                    title=reporter_for_attr
                >
                    {reporter_display}
                </code>
            </p>
            {if body_empty {
                view! {
                    <p class="report-list__body report-list__body--empty">
                        "(no reason supplied by reporter)"
                    </p>
                }.into_any()
            } else {
                view! {
                    <p class="report-list__body">{body_text}</p>
                }.into_any()
            }}
            <p class=move || format!("report-list__reputation {band_class}")
               aria-label=band_label>
                <span class="report-list__reputation-band">{band_label}</span>
                " — "
                <span class="report-list__reputation-detail">{band_summary}</span>
            </p>
            <div class="report-list__actions" role="group" aria-label="Report actions">
                <button
                    type="button"
                    class="report-list__action-btn report-list__action-btn--ack"
                    disabled=move || matches!(outcome_for_buttons.get(), ActionOutcome::Pending)
                    on:click=on_ack
                    title="Record a no-action observation — keep the case open but mark the report seen."
                >
                    "Acknowledge"
                </button>
                <button
                    type="button"
                    class="report-list__action-btn report-list__action-btn--dismiss"
                    disabled=move || matches!(outcome_for_buttons.get(), ActionOutcome::Pending)
                    on:click=on_dismiss
                    title="Close the report as not a policy violation."
                >
                    "Dismiss"
                </button>
                <button
                    type="button"
                    class="report-list__action-btn report-list__action-btn--escalate"
                    disabled=move || matches!(outcome_for_buttons.get(), ActionOutcome::Pending)
                    on:click=on_escalate
                    title="Flag for senior review."
                >
                    "Escalate"
                </button>
                <button
                    type="button"
                    class="report-list__action-btn report-list__action-btn--mute-reporter"
                    disabled=move || matches!(outcome_for_buttons.get(), ActionOutcome::Pending)
                    on:click=on_mute_reporter
                    title="Silently drop future reports from this DID (anti-abuse)."
                >
                    "Ignore reporter"
                </button>
            </div>
            {move || render_action_feedback(outcome_for_feedback.get())}
        </li>
    }
}

/// Fire-and-forget POST to `/api/moderation/muted-reporters` to
/// add the reporter DID to the silent-drop list (anti-abuse, #192).
/// On success the row's feedback line surfaces "Reporter muted";
/// on failure the typed error is rendered.
fn spawn_mute_reporter(reporter_did: String, outcome: RwSignal<ActionOutcome>) {
    // Compute the reason text first (borrows `reporter_did`); then
    // move the DID into the body. This avoids a `.clone()` clippy
    // would flag as redundant under `redundant_clone`.
    let reason = format!("Muted from report card by moderator review of {reporter_did}",);
    let body = MuteReporterBody {
        reporter_did,
        reason,
        until: None,
    };
    spawn_local(async move {
        let client = match default_client("") {
            Ok(c) => c,
            Err(err) => {
                outcome.set(ActionOutcome::Error(describe_error(&err)));
                return;
            }
        };
        match client.mute_reporter(body).await {
            Ok(_) => outcome.set(ActionOutcome::Success(
                "Reporter muted — future reports from this DID will be silently dropped."
                    .to_owned(),
            )),
            Err(err) => outcome.set(ActionOutcome::Error(describe_error(&err))),
        }
    });
}

/// Render the per-row feedback line based on the action outcome.
fn render_action_feedback(outcome: ActionOutcome) -> AnyView {
    match outcome {
        ActionOutcome::None => ().into_any(),
        ActionOutcome::Pending => view! {
            <p class="report-list__action-feedback" role="status">
                "Submitting action…"
            </p>
        }
        .into_any(),
        ActionOutcome::Success(msg) => view! {
            <p class="report-list__action-feedback report-list__action-feedback--success"
               role="status">
                {msg}
            </p>
        }
        .into_any(),
        ActionOutcome::Error(msg) => view! {
            <p class="report-list__action-feedback report-list__action-feedback--error"
               role="status">
                "Failed: "{msg}
            </p>
        }
        .into_any(),
    }
}

/// Fire-and-forget action submission against the case-view's
/// `submit_action` endpoint. The `outcome` signal is updated when
/// the request completes so the row's feedback line refreshes.
///
/// `report_id` is `Some(_)` for the per-report quick-action buttons
/// (Ack / Dismiss / Escalate) — the backend uses it to dedupe a
/// double-click into one stored action and to hide the actioned
/// report on the next case-view render (issue #202). The
/// Mute-Reporter button (which is reporter-level, not report-level)
/// uses [`spawn_mute_reporter`] and never reaches this function.
fn spawn_action(
    subject_id: SubjectId,
    incident_id: IncidentId,
    kind: ActionKind,
    reasoning: String,
    report_id: Option<ReportId>,
    outcome: RwSignal<ActionOutcome>,
) {
    let body = SubmitAction {
        incident_id,
        kind,
        label: None,
        reasoning,
        policy_refs: vec![PolicyId::new(DEFAULT_POLICY_REF)],
        reversible_until: Utc::now() + Duration::hours(REVERSIBLE_WINDOW_HOURS),
        reverses_action_id: None,
        report_id,
    };
    spawn_local(async move {
        let client = match default_client("") {
            Ok(c) => c,
            Err(err) => {
                outcome.set(ActionOutcome::Error(describe_error(&err)));
                return;
            }
        };
        match client.submit_action(subject_id, body).await {
            Ok(action) => {
                outcome.set(ActionOutcome::Success(format!(
                    "Action recorded ({}, reversible until {})",
                    action.kind.as_str(),
                    action.reversible_until.format("%Y-%m-%d %H:%M UTC"),
                )));
            }
            Err(err) => {
                outcome.set(ActionOutcome::Error(describe_error(&err)));
            }
        }
    });
}

/// Convert an [`ApiError`] into a short operator-readable string.
fn describe_error(err: &ApiError) -> String {
    match err {
        ApiError::Transport(msg) => format!("transport: {msg}"),
        ApiError::Http { status, message } => format!("HTTP {status}: {message}"),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    reason = "test code is allowed to panic — rust-quality §7 convention; \
              float_cmp on the band-threshold sentinel values is intentional"
)]
mod tests {
    use super::*;

    fn ctx(filed: i64, actioned: i64, score: f32, age: i64) -> ReporterContext {
        ReporterContext {
            did: "did:plc:test".to_owned(),
            reports_filed: filed,
            reports_actioned: actioned,
            reputation_score: score,
            account_age_days: age,
        }
    }

    #[test]
    fn brand_new_reporter_classified_as_brand_new() {
        let c = ctx(0, 0, 0.0, 0);
        assert_eq!(classify(&c), ReputationBand::BrandNew);
    }

    #[test]
    fn unproven_reporter_has_filed_but_no_actioned() {
        let c = ctx(5, 0, 0.0, 30);
        assert_eq!(classify(&c), ReputationBand::Unproven);
    }

    #[test]
    fn high_score_reporter_is_trusted() {
        let c = ctx(10, 8, 0.8, 365);
        assert_eq!(classify(&c), ReputationBand::Trusted);
    }

    #[test]
    fn low_score_reporter_with_actioned_history_is_noisy() {
        let c = ctx(10, 2, 0.2, 90);
        assert_eq!(classify(&c), ReputationBand::NoisyOrAdversarial);
    }

    #[test]
    fn band_modifier_is_unique_per_band() {
        use std::collections::HashSet;
        let mods: HashSet<&'static str> = [
            ReputationBand::BrandNew.modifier(),
            ReputationBand::Unproven.modifier(),
            ReputationBand::Trusted.modifier(),
            ReputationBand::NoisyOrAdversarial.modifier(),
        ]
        .into_iter()
        .collect();
        assert_eq!(mods.len(), 4, "modifiers must be distinct");
    }

    #[test]
    fn band_label_never_empty() {
        for band in [
            ReputationBand::BrandNew,
            ReputationBand::Unproven,
            ReputationBand::Trusted,
            ReputationBand::NoisyOrAdversarial,
        ] {
            assert!(!band.label().is_empty(), "label for {band:?} is empty");
        }
    }
}
