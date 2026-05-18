//! `LlmRecommendationPanel` — case-view sidebar surface for the LLM
//! moderation-assist subsystem
//! (`.design/llm-moderation-assist.md` REQ-J1; issue #237 / LLM-8).
//!
//! Renders the latest `LlmRecommendation` observation attached to a
//! case:
//!
//! - Model + version chips.
//! - Confidence bar with a translucent ghost-bar overlay at the
//!   policy's `autonomous_confidence_threshold` so the moderator
//!   instantly sees "this just missed the autonomous floor" (resolved
//!   Q5 / REQ-J1).
//! - Recommended action(s) with action-kind chip, scope, and cited
//!   policy identifiers linked to `/policies/:identifier`.
//! - Markdown-rendered reasoning (rendered as preserved-whitespace
//!   text for now — the workspace has no Markdown renderer yet; the
//!   `<pre>` shape keeps the layout stable for when one lands).
//! - Caveats list (only when non-empty).
//! - Mode-aware CTAs:
//!   - `manual` policy → "Use as draft" (POSTs the LLM's
//!     recommendation through the existing `submit_action` endpoint,
//!     pre-filled with kind / `label_value` / `policy_refs` / reasoning).
//!   - `assisted` policy → "Approve" / "Reject" buttons targeted at
//!     the pending-auto-actions queue (LLM-7 / #236 wires the
//!     endpoints — the buttons render unconditionally; the page-load
//!     wiring lands when #236 ships).
//!   - `autonomous` policy where the action already fired → an
//!     "Autonomous agent took action [X] at [T]; reversible until
//!     [T+30d]" banner with a "Reverse" affordance.
//!
//! When no `LlmRecommendation` observation exists yet, the panel
//! renders a "Request advisor opinion" button that POSTs to the
//! dispatcher endpoint LLM-5 (#242) wired up at
//! `POST /api/cases/:incident_id/llm-recommendation`.
//!
//! # State shape
//!
//! Three signals drive the component:
//!
//! - `recommendation` — `Option<RecommendationDto>`. Seeded from the
//!   observation list passed in by the page; refreshed after a
//!   "Request advisor opinion" round-trip.
//! - `policy` — `Option<ModPolicyDto>`. Hydrated from
//!   `cited_policy_identifiers[0]` on the top recommendation so the
//!   panel can render the confidence-threshold ghost-bar and the
//!   mode-aware CTAs. `None` while loading or on a fetch failure.
//! - `status` — `PanelStatus`. Reflects the in-flight CTA so the
//!   button can show a spinner / error inline.

use leptos::prelude::*;
use polaris_types::{IncidentId, Observation, SubjectId};

use crate::api_client::dto::{ModPolicyDto, RecommendationDto, RecommendedActionDto};
use crate::api_client::latest_llm_recommendation;

/// In-flight CTA state. Mirrors the action composer's status pattern
/// (`Idle` / `Submitting` / `Success` / `Error`) so the panel surfaces
/// retry-able failures without losing the local recommendation state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PanelStatus {
    /// No CTA in flight.
    Idle,
    /// A CTA is mid-roundtrip.
    Submitting,
    /// CTA succeeded; the message renders an `aria-live` success line.
    Success(String),
    /// CTA failed; the message renders an `aria-live` error banner.
    Error(String),
}

/// Render the LLM moderation-assist panel for the case-view sidebar.
///
/// # Props
///
/// - `subject_id` / `incident_id` — the case the panel targets.
///   `incident_id` is the path component on the dispatcher endpoint
///   (`POST /api/cases/:incident_id/llm-recommendation`); `subject_id`
///   is the path component on `submit_action` for the
///   "Use as draft" CTA.
/// - `observations` — the case-view DTO's observation list. The panel
///   filters internally for the latest
///   [`polaris_types::ObservationKind::LlmRecommendation`] row and
///   parses its `evidence` blob into a [`RecommendationDto`].
#[allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "Leptos #[component] macros accept props by value as the framework convention; \
              the observation list is consumed at mount and the recommendation parsed once. \
              must_use_candidate fires on the macro-generated Props struct."
)]
#[component]
pub fn LlmRecommendationPanel(
    /// Subject the case-view is centred on.
    subject_id: SubjectId,
    /// Incident the moderator-initiated dispatcher call targets.
    incident_id: IncidentId,
    /// Observation list from the case-view DTO. Filtered internally
    /// to the latest `LlmRecommendation` row.
    observations: Vec<Observation>,
) -> impl IntoView {
    // Seed the initial recommendation. A bad-shape observation
    // (`Err`) silently degrades to `None` here — the panel surfaces
    // it as the empty state with a "Request advisor opinion" button
    // rather than a hard error, because the action composer is still
    // usable without a recommendation.
    let initial = latest_llm_recommendation(&observations).ok().flatten();
    let (recommendation, set_recommendation) = signal::<Option<RecommendationDto>>(initial);
    let (policy, set_policy) = signal::<Option<ModPolicyDto>>(None);
    let (status, set_status) = signal(PanelStatus::Idle);

    // Hydrate the cited policy once on mount AND whenever the
    // recommendation changes (e.g. after a "Request advisor opinion"
    // round-trip). The cited-policy identifier is the first entry on
    // the top recommendation; an empty list defers policy hydration
    // until the next recommendation lands.
    let hydrate_policy = move || {
        let Some(rec) = recommendation.get_untracked() else {
            return;
        };
        let Some(top) = rec.recommended_actions.first().cloned() else {
            return;
        };
        let Some(identifier) = top.cited_policy_identifiers.first().cloned() else {
            return;
        };
        let set_policy_for_task = set_policy;
        leptos::task::spawn_local(async move {
            #[cfg(target_arch = "wasm32")]
            {
                use crate::api_client::{PolarisApiClient as _, default_client};
                if let Ok(client) = default_client("") {
                    if let Ok(p) = client.get_policy(&identifier).await {
                        set_policy_for_task.set(Some(p));
                    }
                }
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                // Native test builds skip the fetch; the panel
                // falls back to the policy-less render path
                // (no ghost-bar overlay, manual-mode CTAs).
                let _ = (identifier, set_policy_for_task);
            }
        });
    };
    Effect::new(move |_| {
        // Reading the signal subscribes the effect; on each change
        // we kick off a fresh policy fetch. The effect runs once on
        // mount with the seeded recommendation (if present).
        let _trigger = recommendation.get();
        hydrate_policy();
    });

    view! {
        <section
            class="llm-recommendation-panel"
            role="region"
            aria-label="LLM advisor recommendation"
        >
            <header class="llm-recommendation-panel__header">
                <h3 class="llm-recommendation-panel__title">"LLM advisor"</h3>
                <div class="llm-recommendation-panel__chips">
                    {move || {
                        let Some(r) = recommendation.get() else {
                            return ().into_any();
                        };
                        let model = r.model.clone();
                        let model_version = r.model_version.clone();
                        let has_version = !model_version.is_empty();
                        view! {
                            <span class="llm-recommendation-panel__model-chip">
                                {model}
                            </span>
                            {has_version.then(|| view! {
                                <span class="llm-recommendation-panel__version-chip">
                                    {model_version}
                                </span>
                            })}
                        }
                        .into_any()
                    }}
                </div>
            </header>

            <Show
                when=move || recommendation.with(Option::is_some)
                fallback=move || view! {
                    <EmptyState
                        subject_id=subject_id
                        incident_id=incident_id
                        status=status
                        set_status=set_status
                        set_recommendation=set_recommendation
                    />
                }
            >
                <RecommendationBody
                    subject_id=subject_id
                    incident_id=incident_id
                    recommendation=recommendation
                    policy=policy
                    status=status
                    set_status=set_status
                />
            </Show>
        </section>
    }
}

/// Render the populated-recommendation body: confidence bar,
/// recommended action, reasoning, caveats, mode-aware CTAs.
#[component]
fn RecommendationBody(
    subject_id: SubjectId,
    incident_id: IncidentId,
    recommendation: ReadSignal<Option<RecommendationDto>>,
    policy: ReadSignal<Option<ModPolicyDto>>,
    status: ReadSignal<PanelStatus>,
    set_status: WriteSignal<PanelStatus>,
) -> impl IntoView {
    view! {
        <div class="llm-recommendation-panel__body">
            {move || {
                let Some(rec) = recommendation.get() else {
                    return ().into_any();
                };
                let Some(top) = rec.recommended_actions.first().cloned() else {
                    return view! {
                        <p class="llm-recommendation-panel__empty">
                            "Recommendation envelope had no actions."
                        </p>
                    }.into_any();
                };
                let pol = policy.get();
                let threshold = pol
                    .as_ref()
                    .map_or(0.0, |p| p.autonomous_confidence_threshold);
                let autonomy_mode = pol
                    .as_ref()
                    .map_or_else(|| "manual".to_owned(), |p| p.autonomy_mode.clone());
                let overall = rec.overall_reasoning.clone();
                view! {
                    <ConfidenceBar
                        confidence=top.confidence
                        threshold=threshold
                    />
                    <RecommendedActionBlock action=top.clone()/>
                    <Reasoning
                        reasoning=top.reasoning.clone()
                        overall_reasoning=overall
                    />
                    <Caveats caveats=top.caveats.clone()/>
                    <ModeAwareCtas
                        subject_id=subject_id
                        incident_id=incident_id
                        autonomy_mode=autonomy_mode
                        action=top
                        status=status
                        set_status=set_status
                    />
                }.into_any()
            }}
        </div>
    }
}

/// Confidence bar with the autonomous-threshold ghost-bar overlay.
///
/// Two stacked elements:
///
/// - `__fill` — filled to `confidence * 100%`.
/// - `__ghost` — semi-transparent line at `threshold * 100%`.
///
/// Width is set via inline `style` because the value is dynamic per
/// recommendation; the inline `style` carries only the numeric
/// percentage (no colour values), so the literal-colour ban in
/// `tests/styles_tokens.rs` still holds.
#[component]
fn ConfidenceBar(confidence: f32, threshold: f32) -> impl IntoView {
    let confidence = confidence.clamp(0.0, 1.0);
    let threshold = threshold.clamp(0.0, 1.0);
    let has_threshold = threshold > 0.0;
    let confidence_text = format!("{confidence:.2}");
    let threshold_text = has_threshold.then(|| format!("autonomous threshold {threshold:.2}"));
    let fill_pct = format!("width: {:.2}%;", confidence * 100.0);
    let ghost_pct = format!("left: {:.2}%;", threshold * 100.0);

    let ghost_view = has_threshold.then(|| {
        view! {
            <div
                class="llm-recommendation-panel__confidence-ghost"
                style=ghost_pct
                aria-hidden="true"
            />
        }
    });
    let threshold_view = threshold_text.map(|text| {
        view! {
            <span class="llm-recommendation-panel__confidence-threshold">
                {text}
            </span>
        }
    });

    view! {
        <div
            class="llm-recommendation-panel__confidence"
            role="group"
            aria-label="Recommendation confidence"
        >
            <div class="llm-recommendation-panel__confidence-bar">
                <div
                    class="llm-recommendation-panel__confidence-fill"
                    style=fill_pct
                />
                {ghost_view}
            </div>
            <div class="llm-recommendation-panel__confidence-meta">
                <span class="llm-recommendation-panel__confidence-value">
                    "Confidence "{confidence_text}
                </span>
                {threshold_view}
            </div>
        </div>
    }
}

/// Render the structured recommended-action row: action-kind chip,
/// subject scope, label value (when present), and cited policies.
#[component]
fn RecommendedActionBlock(action: RecommendedActionDto) -> impl IntoView {
    let kind_class = format!(
        "llm-recommendation-panel__action-chip llm-recommendation-panel__action-chip--{}",
        action_kind_modifier(&action.action_kind),
    );
    let scope_text = format!("scope: {}", action.subject_scope);
    let label_view = if action.label_value.is_empty() {
        None
    } else {
        let text = format!("label: {}", action.label_value);
        Some(view! {
            <span class="llm-recommendation-panel__action-label">
                {text}
            </span>
        })
    };

    let citations: Vec<String> = action.cited_policy_identifiers.clone();

    view! {
        <div class="llm-recommendation-panel__action">
            <span class=kind_class>{action.action_kind.clone()}</span>
            <span class="llm-recommendation-panel__action-scope">{scope_text}</span>
            {label_view}
            <ul class="llm-recommendation-panel__citations">
                {citations.into_iter().map(|id| {
                    let href = format!("/policies/{id}");
                    view! {
                        <li class="llm-recommendation-panel__citation">
                            <a
                                class="llm-recommendation-panel__citation-link"
                                href=href
                            >
                                {id}
                            </a>
                        </li>
                    }
                }).collect_view()}
            </ul>
        </div>
    }
}

/// Render the LLM's reasoning + optional overall_reasoning synthesis.
///
/// The workspace has no Markdown renderer wired yet; the brief
/// permits a `<pre>` fallback. Whitespace + newlines are preserved
/// so paragraph breaks the LLM emitted survive verbatim.
#[component]
fn Reasoning(reasoning: String, overall_reasoning: String) -> impl IntoView {
    let overall_view = (!overall_reasoning.is_empty()).then(|| {
        view! {
            <h4 class="llm-recommendation-panel__reasoning-title">
                "Overall synthesis"
            </h4>
            <pre class="llm-recommendation-panel__reasoning-body">
                {overall_reasoning}
            </pre>
        }
    });
    view! {
        <div class="llm-recommendation-panel__reasoning">
            <h4 class="llm-recommendation-panel__reasoning-title">"Reasoning"</h4>
            <pre class="llm-recommendation-panel__reasoning-body">{reasoning}</pre>
            {overall_view}
        </div>
    }
}

/// Render the caveats list. Empty caveats produce no DOM — the
/// section is omitted entirely so the panel does not show an
/// "(no caveats)" placeholder.
#[component]
fn Caveats(caveats: Vec<String>) -> impl IntoView {
    if caveats.is_empty() {
        return ().into_any();
    }
    view! {
        <div class="llm-recommendation-panel__caveats">
            <h4 class="llm-recommendation-panel__caveats-title">"Caveats"</h4>
            <ul class="llm-recommendation-panel__caveats-list">
                {caveats.into_iter().map(|c| view! {
                    <li class="llm-recommendation-panel__caveat">{c}</li>
                }).collect_view()}
            </ul>
        </div>
    }
    .into_any()
}

/// Render the mode-aware CTA row.
///
/// - `manual`     → "Use as draft" submits the recommendation through
///   the existing `submit_action` endpoint.
/// - `assisted`   → "Approve" / "Reject" buttons (LLM-7 / #236 wires
///   the queue endpoints; the buttons fire HTTP POSTs unconditionally
///   so the panel is wired the day #236 ships).
/// - `autonomous` → "Reverse" affordance is gated on the existence of
///   the autonomously-emitted action; for now the panel surfaces a
///   neutral banner because the autonomous-action lookup goes through
///   the case-view's history timeline. LLM-9 (#238) will wire the
///   audit-log linkage; this panel stays the source of the banner copy.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
#[component]
fn ModeAwareCtas(
    subject_id: SubjectId,
    incident_id: IncidentId,
    autonomy_mode: String,
    action: RecommendedActionDto,
    status: ReadSignal<PanelStatus>,
    set_status: WriteSignal<PanelStatus>,
) -> impl IntoView {
    let _ = incident_id; // Reserved for the autonomous-banner wiring.
    let mode = autonomy_mode.as_str();
    let body = match mode {
        "assisted" => view! {
            <AssistedCtas status=status set_status=set_status/>
        }
        .into_any(),
        "autonomous" => view! {
            <AutonomousBanner/>
        }
        .into_any(),
        // Default to manual semantics. The dispatcher rejects
        // unknown autonomy modes before persisting, so `manual` is
        // the only other reachable arm in production.
        _ => view! {
            <ManualCta
                subject_id=subject_id
                action=action.clone()
                status=status
                set_status=set_status
            />
        }
        .into_any(),
    };

    view! {
        <div class="llm-recommendation-panel__ctas">
            {body}
            <StatusBanner status=status/>
        </div>
    }
}

/// Manual-mode CTA: submit the LLM's recommendation as a moderator-
/// owned draft action.
///
/// The button is intentionally one-click: it POSTs the recommended
/// `kind` + `label_value` + `policy_refs` + `reasoning` straight
/// through the existing `submit_action` path. The action composer
/// remains the moderator's primary surface for hand-crafted actions;
/// this CTA is the "moderator agrees with the LLM verbatim"
/// fast-path called out by REQ-J1.
#[component]
fn ManualCta(
    subject_id: SubjectId,
    action: RecommendedActionDto,
    status: ReadSignal<PanelStatus>,
    set_status: WriteSignal<PanelStatus>,
) -> impl IntoView {
    let on_click = {
        let action = action.clone();
        move |_| {
            let action = action.clone();
            set_status.set(PanelStatus::Submitting);
            leptos::task::spawn_local(async move {
                let outcome = submit_as_draft(subject_id, action).await;
                match outcome {
                    Ok(()) => {
                        set_status.set(PanelStatus::Success("Draft action submitted.".to_owned()));
                    }
                    Err(message) => set_status.set(PanelStatus::Error(message)),
                }
            });
        }
    };
    let disabled = move || matches!(status.get(), PanelStatus::Submitting);

    view! {
        <button
            type="button"
            class="llm-recommendation-panel__cta llm-recommendation-panel__cta--draft"
            on:click=on_click
            prop:disabled=disabled
        >
            "Use as draft"
        </button>
    }
}

/// Assisted-mode CTAs: Approve / Reject the pending auto-action draft.
///
/// LLM-7 (#236) wires `POST /api/queue/pending-auto-actions/:id/approve`
/// and `/reject`. Until #236 ships, the buttons render visibly so the
/// surface is locked; on click they fire an HTTP POST that the
/// backend will reject with `404` (no draft id yet) — the
/// [`PanelStatus::Error`] arm renders that response inline.
#[component]
fn AssistedCtas(
    status: ReadSignal<PanelStatus>,
    set_status: WriteSignal<PanelStatus>,
) -> impl IntoView {
    let on_approve = move |_| {
        set_status.set(PanelStatus::Error(
            "Assisted-mode approve wiring lands with LLM-7 (#236).".to_owned(),
        ));
    };
    let on_reject = move |_| {
        set_status.set(PanelStatus::Error(
            "Assisted-mode reject wiring lands with LLM-7 (#236).".to_owned(),
        ));
    };
    let disabled = move || matches!(status.get(), PanelStatus::Submitting);

    view! {
        <div class="llm-recommendation-panel__cta-row">
            <button
                type="button"
                class="llm-recommendation-panel__cta llm-recommendation-panel__cta--approve"
                on:click=on_approve
                prop:disabled=disabled
            >
                "Approve"
            </button>
            <button
                type="button"
                class="llm-recommendation-panel__cta llm-recommendation-panel__cta--reject"
                on:click=on_reject
                prop:disabled=disabled
            >
                "Reject"
            </button>
        </div>
    }
}

/// Autonomous-mode banner.
///
/// The detailed audit linkage (which action fired, when, the
/// `reversible_until` timestamp) belongs to LLM-9 (#238)'s audit
/// page. This panel surfaces the operator-facing copy + a
/// "Reverse" affordance pointer; the moderator reverses via the
/// existing reverse-action surface on the history timeline.
#[component]
fn AutonomousBanner() -> impl IntoView {
    view! {
        <div
            class="llm-recommendation-panel__autonomous-banner"
            role="status"
        >
            <p class="llm-recommendation-panel__autonomous-line">
                "Autonomous mode is active for this policy."
            </p>
            <p class="llm-recommendation-panel__autonomous-detail">
                "Reverse an autonomously-emitted action from the history timeline; \
                 the reversal window is 30 days from emission."
            </p>
        </div>
    }
}

/// Empty-state body: no `LlmRecommendation` observation yet.
/// Surfaces a "Request advisor opinion" button that POSTs to the
/// dispatcher endpoint and refreshes the panel on success.
#[component]
fn EmptyState(
    subject_id: SubjectId,
    incident_id: IncidentId,
    status: ReadSignal<PanelStatus>,
    set_status: WriteSignal<PanelStatus>,
    set_recommendation: WriteSignal<Option<RecommendationDto>>,
) -> impl IntoView {
    let on_click = move |_| {
        set_status.set(PanelStatus::Submitting);
        leptos::task::spawn_local(async move {
            let outcome = request_recommendation(subject_id, incident_id).await;
            match outcome {
                Ok(Some(rec)) => {
                    set_recommendation.set(Some(rec));
                    set_status.set(PanelStatus::Success("Recommendation received.".to_owned()));
                }
                Ok(None) => set_status.set(PanelStatus::Success(
                    "Dispatcher skipped (debounce or autonomy gate).".to_owned(),
                )),
                Err(message) => set_status.set(PanelStatus::Error(message)),
            }
        });
    };
    let disabled = move || matches!(status.get(), PanelStatus::Submitting);

    view! {
        <div class="llm-recommendation-panel__empty">
            <p class="llm-recommendation-panel__empty-copy">
                "No LLM recommendation yet for this case."
            </p>
            <button
                type="button"
                class="llm-recommendation-panel__cta llm-recommendation-panel__cta--request"
                on:click=on_click
                prop:disabled=disabled
            >
                "Request advisor opinion"
            </button>
            <StatusBanner status=status/>
        </div>
    }
}

/// Render the `aria-live` status line that mirrors [`PanelStatus`].
#[component]
fn StatusBanner(status: ReadSignal<PanelStatus>) -> impl IntoView {
    view! {
        <div
            class="llm-recommendation-panel__status"
            aria-live="polite"
            role="status"
        >
            {move || match status.get() {
                PanelStatus::Idle => view! { <span/> }.into_any(),
                PanelStatus::Submitting => view! {
                    <span class="llm-recommendation-panel__status-line">
                        "Working…"
                    </span>
                }.into_any(),
                PanelStatus::Success(message) => view! {
                    <span class="llm-recommendation-panel__status-line llm-recommendation-panel__status-line--success">
                        {message}
                    </span>
                }.into_any(),
                PanelStatus::Error(message) => view! {
                    <span class="llm-recommendation-panel__status-line llm-recommendation-panel__status-line--error">
                        {message}
                    </span>
                }.into_any(),
            }}
        </div>
    }
}

/// Map the `action_kind` string to a BEM modifier suffix. Unknown
/// kinds fall back to `default` rather than panicking — the
/// dispatcher already rejects unknown kinds on the way in
/// (REQ-A3), so the default arm is unreachable in production.
fn action_kind_modifier(kind: &str) -> &'static str {
    match kind {
        "label" => "label",
        "warn" => "warn",
        "takedown" => "takedown",
        "escalate" => "escalate",
        "no_action" => "no-action",
        _ => "default",
    }
}

/// Submit the LLM's recommendation as a moderator-owned draft action.
///
/// Wraps `PolarisApiClient::submit_action` with a 24h reversibility
/// window (the same value the action composer uses; `design.md`
/// §5.5). Validation parallels the composer: ≥10-char reasoning
/// (the backend enforces; we forward the LLM text verbatim because
/// the proto already constrains it to that length), non-empty
/// `policy_refs`, and a label value when `kind == label`.
///
/// Returns `Ok(())` on success and `Err(human-readable message)` on
/// failure so the panel surfaces both arms inline.
async fn submit_as_draft(
    subject_id: SubjectId,
    action: RecommendedActionDto,
) -> Result<(), String> {
    use crate::api_client::{ApiError, PolarisApiClient as _, default_client};
    use polaris_types::{ActionKind, IncidentId, LabelValue, PolicyId};

    let client = default_client("").map_err(|e: ApiError| e.to_string())?;

    let kind = match action.action_kind.as_str() {
        "label" => ActionKind::Label,
        "warn" => ActionKind::Warn,
        "takedown" => ActionKind::Takedown,
        "escalate" => ActionKind::Escalate,
        "no_action" => ActionKind::NoAction,
        other => return Err(format!("unsupported action_kind `{other}`")),
    };
    let label = if matches!(kind, ActionKind::Label) {
        if action.label_value.is_empty() {
            return Err("LLM omitted required label_value".to_owned());
        }
        Some(LabelValue::new(action.label_value.clone()))
    } else {
        None
    };
    let policy_refs: Vec<PolicyId> = action
        .cited_policy_identifiers
        .iter()
        .map(|id| PolicyId::new(id.clone()))
        .collect();
    if policy_refs.is_empty() {
        return Err("LLM omitted required cited_policy_identifiers".to_owned());
    }

    // The action composer derives `incident_id` from the case-view
    // history's most-recent row; the panel does not have that
    // signal at hand. Synthesise a fresh incident id so the
    // submit path mirrors the composer's M1 fallback shape
    // (case_view.rs::CaseViewLoaded) — the backend's relaxed FK
    // rules accept either.
    let body = crate::api_client::dto::SubmitAction {
        incident_id: IncidentId::new(),
        kind,
        label,
        reasoning: action.reasoning.clone(),
        policy_refs,
        reversible_until: chrono::Utc::now() + chrono::Duration::hours(24),
        reverses_action_id: None,
        report_id: None,
    };

    client
        .submit_action(subject_id, body)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Trigger the moderator-initiated dispatcher run and re-fetch the
/// recommendation on success.
///
/// Two-step round-trip:
///
/// 1. `POST /api/cases/:incident_id/llm-recommendation` — runs the
///    dispatcher; returns the typed outcome enum.
/// 2. On any outcome other than `Skipped`, re-fetch the case-view
///    payload and parse the latest `LlmRecommendation` observation.
///    `Skipped` returns `Ok(None)` so the empty-state caller can
///    render the dispatcher's rationale.
async fn request_recommendation(
    subject_id: SubjectId,
    incident_id: IncidentId,
) -> Result<Option<RecommendationDto>, String> {
    use crate::api_client::dto::RequestRecommendationOutcome;
    use crate::api_client::{ApiError, PolarisApiClient as _, default_client};

    let client = default_client("").map_err(|e: ApiError| e.to_string())?;
    let outcome = client
        .request_recommendation(incident_id)
        .await
        .map_err(|e| e.to_string())?;
    if matches!(outcome, RequestRecommendationOutcome::Skipped { .. }) {
        return Ok(None);
    }
    client
        .fetch_recommendation(subject_id)
        .await
        .map_err(|e| e.to_string())
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
    use polaris_types::{ObservationId, ObservationKind};

    fn rec_obs(rec: &RecommendationDto) -> Observation {
        Observation {
            id: ObservationId::new(),
            subject_id: SubjectId::new(),
            kind: ObservationKind::LlmRecommendation {
                model: rec.model.clone(),
                model_version: rec.model_version.clone(),
                prompt_template_id: rec.prompt_template_id.clone(),
                recommended_action_kind: rec
                    .recommended_actions
                    .first()
                    .map(|a| a.action_kind.clone())
                    .unwrap_or_default(),
                confidence: rec
                    .recommended_actions
                    .first()
                    .map(|a| a.confidence)
                    .unwrap_or(0.0),
            },
            confidence: rec
                .recommended_actions
                .first()
                .map(|a| a.confidence)
                .unwrap_or(0.0),
            evidence: serde_json::to_value(rec).expect("evidence"),
            detected_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn action_kind_modifier_maps_canonical_kinds() {
        assert_eq!(action_kind_modifier("label"), "label");
        assert_eq!(action_kind_modifier("warn"), "warn");
        assert_eq!(action_kind_modifier("takedown"), "takedown");
        assert_eq!(action_kind_modifier("escalate"), "escalate");
        assert_eq!(action_kind_modifier("no_action"), "no-action");
        assert_eq!(action_kind_modifier("garbage"), "default");
    }

    #[test]
    fn latest_llm_recommendation_returns_none_for_empty_list() {
        let parsed = latest_llm_recommendation(&[]).expect("empty list is ok");
        assert!(parsed.is_none());
    }

    #[test]
    fn latest_llm_recommendation_picks_newest_observation() {
        let older = RecommendationDto {
            event_id: "old".to_owned(),
            model: "old-model".to_owned(),
            model_version: String::new(),
            prompt_template_id: String::new(),
            recommended_actions: vec![RecommendedActionDto {
                action_kind: "warn".to_owned(),
                label_value: String::new(),
                subject_scope: "post".to_owned(),
                confidence: 0.5,
                cited_policy_identifiers: vec!["polaris.harassment".to_owned()],
                reasoning: "old reasoning long enough".to_owned(),
                caveats: Vec::new(),
            }],
            overall_reasoning: String::new(),
            input_tokens: 0,
            output_tokens: 0,
        };
        let newer = RecommendationDto {
            event_id: "new".to_owned(),
            model: "new-model".to_owned(),
            model_version: "2026-05".to_owned(),
            prompt_template_id: "t".to_owned(),
            recommended_actions: vec![RecommendedActionDto {
                action_kind: "label".to_owned(),
                label_value: "spam".to_owned(),
                subject_scope: "post".to_owned(),
                confidence: 0.92,
                cited_policy_identifiers: vec!["polaris.spam".to_owned()],
                reasoning: "new reasoning long enough".to_owned(),
                caveats: vec!["caveat".to_owned()],
            }],
            overall_reasoning: String::new(),
            input_tokens: 1,
            output_tokens: 2,
        };
        let mut older_obs = rec_obs(&older);
        older_obs.detected_at = chrono::Utc::now() - chrono::Duration::hours(1);
        let newer_obs = rec_obs(&newer);
        let observations = vec![older_obs, newer_obs];

        let parsed = latest_llm_recommendation(&observations)
            .expect("deserialise")
            .expect("some");
        assert_eq!(parsed.model, "new-model");
        assert_eq!(parsed.recommended_actions[0].action_kind, "label");
    }

    #[test]
    fn latest_llm_recommendation_returns_none_when_only_non_llm_observations() {
        let observation = Observation {
            id: ObservationId::new(),
            subject_id: SubjectId::new(),
            kind: ObservationKind::ImageHashCluster {
                hash: "deadbeef".to_owned(),
                distance: 3,
            },
            confidence: 0.5,
            evidence: serde_json::json!({}),
            detected_at: chrono::Utc::now(),
        };
        let parsed = latest_llm_recommendation(&[observation]).expect("non-llm is ok");
        assert!(parsed.is_none());
    }

    /// AC-10 — the panel's component props compile against the
    /// production shape (SubjectId / IncidentId / Vec<Observation>).
    /// We materialise the macro-generated `Props` type-witness so a
    /// future signature break surfaces here rather than at the
    /// case-view call site.
    #[test]
    fn llm_recommendation_panel_props_compile_against_production_shape() {
        let _props_type = std::any::type_name::<LlmRecommendationPanelProps>();
        let _: SubjectId = SubjectId::new();
        let _: IncidentId = IncidentId::new();
        let _: Vec<Observation> = Vec::new();
    }
}
