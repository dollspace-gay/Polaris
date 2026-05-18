//! `NetworkPanel` — M2 case-view network-context surface
//! (issue #97).
//!
//! Fetches `GET /api/cases/{subject_id}/network-context` on mount
//! and renders the four signal categories the moderator's case
//! view consumes when deciding on a subject:
//!
//! 1. **Profile signals** — counts, age, pinned
//!    post, `is_labeler` flag.
//! 2. **Follow graph** — recent followers, recent follows,
//!    mutual-follow intersection count.
//! 3. **Reply graph** — accounts the subject replies to + accounts
//!    that reply to the subject's recent posts.
//! 4. **Cohort signals** — top mutual-follow overlap + top
//!    interaction partners (follows ∩ replies-to).
//! 5. **Shared-image clusters** — cross-subject CID matches.
//!
//! Each section renders independently from the response's
//! [`SignalQuality`] flags; an upstream-degraded section surfaces
//! an inline "this signal unavailable" hint rather than a blank
//! gap. The panel is read-only — clicking elements does not
//! mutate state; future workstreams may wire each actor row to
//! the command-palette lookup so a moderator can pivot from one
//! subject to another with one click.

#![allow(
    clippy::must_use_candidate,
    reason = "Leptos #[component] attribute strips outer attributes; consumers always feed the return value into view!"
)]

use leptos::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::api_client::dto::{
    ActivityPattern, CohortSignals, DailyPostCount, FollowGraph, MatchedSubject, NetworkActor,
    NetworkContext, ReplyGraph, SharedImageSignals, SignalQuality,
};
use polaris_types::SubjectId;

/// Internal fetch state. Lives behind the wasm cfg gate because the
/// fetch only runs on wasm; on native the panel renders a static
/// stub instead, so the enum has no native consumer and no
/// dead-code lint to silence.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "`NetworkContext` is much bigger than `Loading` / `Failed(String)` — boxing the \
              variant would force every render to chase an extra pointer for the common \
              Ready case; the size penalty is acceptable for a once-per-case-view enum."
)]
enum FetchState {
    /// Initial state — the on-mount `spawn_local` is in flight.
    Loading,
    /// Fetch completed successfully.
    Ready(NetworkContext),
    /// Fetch failed; surface the error inline so the moderator
    /// knows the panel is degraded.
    Failed(String),
}

/// Network-context panel.
///
/// # Accessibility
///
/// The panel is a `role="region" aria-label="Network context"`
/// section. Each sub-section is its own `<section>` with an
/// `<h3>` heading so screen readers can navigate between the
/// signal categories.
#[component]
pub fn NetworkPanel(
    /// Subject this panel describes. Used as the URL path
    /// parameter for the backend fetch.
    subject_id: SubjectId,
) -> impl IntoView {
    #[cfg(target_arch = "wasm32")]
    {
        render_wasm(subject_id)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = subject_id;
        render_native_stub()
    }
}

/// On native (test / IDE check) there is no backend to consult;
/// render the panel shell with the same loading row the wasm path
/// shows while the fetch is in flight.
#[cfg(not(target_arch = "wasm32"))]
fn render_native_stub() -> AnyView {
    view! {
        <section
            class="network-panel"
            role="region"
            aria-label="Network context"
        >
            <h2 class="network-panel__title">"Network context"</h2>
            <p class="network-panel__loading" role="status">
                "Loading network context…"
            </p>
        </section>
    }
    .into_any()
}

/// wasm-only render path: owns the fetch state machine, runs the
/// network-context lookup via `spawn_local`, and dispatches on the
/// resulting [`FetchState`].
#[cfg(target_arch = "wasm32")]
fn render_wasm(subject_id: SubjectId) -> AnyView {
    let (state, set_state) = signal(FetchState::Loading);
    {
        use crate::api_client::{PolarisApiClient as _, default_client};
        let id_str = subject_id.0.to_string();
        leptos::task::spawn_local(async move {
            match default_client("") {
                Ok(client) => match client.network_context(&id_str).await {
                    Ok(ctx) => set_state.set(FetchState::Ready(ctx)),
                    Err(e) => set_state.set(FetchState::Failed(e.to_string())),
                },
                Err(e) => set_state.set(FetchState::Failed(e.to_string())),
            }
        });
    }

    view! {
        <section
            class="network-panel"
            role="region"
            aria-label="Network context"
        >
            <h2 class="network-panel__title">"Network context"</h2>
            {move || match state.get() {
                FetchState::Loading => view! {
                    <p class="network-panel__loading" role="status">
                        "Loading network context…"
                    </p>
                }.into_any(),
                FetchState::Failed(msg) => view! {
                    <p class="network-panel__error" role="alert">
                        "Network context unavailable: "{msg}
                    </p>
                }.into_any(),
                FetchState::Ready(ctx) => render_full_panel(&ctx).into_any(),
            }}
        </section>
    }
    .into_any()
}

/// Render the full panel for a successfully-loaded context.
/// Broken out of the component body so the matchback returns
/// `AnyView` once at the leaf.
///
/// Takes `ctx` by reference: every section renderer below clones
/// only the small fields it actually needs into the view!, so we
/// never need ownership of the whole `NetworkContext`. Passing by
/// reference also satisfies `clippy::needless_pass_by_value`.
#[cfg(target_arch = "wasm32")]
fn render_full_panel(ctx: &NetworkContext) -> AnyView {
    let signal_quality = ctx.signal_quality.clone();
    let profile_view = render_profile_section(ctx);
    let follow_graph_view = render_follow_graph_section(&ctx.follow_graph, &signal_quality);
    let activity_view = render_activity_pattern_section(&ctx.activity_pattern);
    let reply_graph_view = render_reply_graph_section(&ctx.reply_graph, &signal_quality);
    let cohort_view = render_cohort_section(&ctx.cohort);
    let shared_images_view = render_shared_images_section(&ctx.shared_images, &signal_quality);
    let source_url = ctx.source_url.clone();
    let source_url_display = source_url.clone();

    view! {
        {profile_view}
        {follow_graph_view}
        {activity_view}
        {reply_graph_view}
        {cohort_view}
        {shared_images_view}
        <p class="network-panel__source">
            "Source: "
            <a href=source_url target="_blank" rel="noreferrer">{source_url_display}</a>
        </p>
    }
    .into_any()
}

/// Profile-signals section — counts, account age, pinned post
/// indicator, `is_labeler` badge. Third-party labels are rendered by
/// the dedicated `ThirdPartyLabelsPanel` below the subject panel,
/// not here, to avoid duplicating the panel surface.
#[cfg(target_arch = "wasm32")]
fn render_profile_section(ctx: &NetworkContext) -> AnyView {
    let did = ctx.did.clone();
    let handle = ctx.handle.clone();
    let display_name = ctx.display_name.clone();
    let description = ctx.description.clone();
    let avatar = ctx.avatar.clone();
    let followers = ctx.followers_count;
    let follows = ctx.follows_count;
    let posts = ctx.posts_count;
    let age = ctx.account_age_days;
    let new_account = age.is_some_and(|d| d <= 7);
    let is_labeler = ctx.is_labeler;
    let pinned = ctx.pinned_post_uri.clone();

    view! {
        <section class="network-panel__profile">
            <div class="network-panel__profile-head">
                {avatar.map(|src| view! {
                    <img
                        class="network-panel__avatar"
                        src=src
                        alt=""
                        loading="lazy"
                    />
                })}
                <div class="network-panel__profile-text">
                    {display_name.map(|n| view! {
                        <p class="network-panel__display-name">{n}</p>
                    })}
                    <p class="network-panel__handle">
                        {handle.unwrap_or_else(|| "(no handle)".to_owned())}
                    </p>
                    <p class="network-panel__did">{did}</p>
                </div>
            </div>
            {description.map(|d| view! {
                <p class="network-panel__description">{d}</p>
            })}
            <dl class="network-panel__stats">
                <div class="network-panel__stat">
                    <dt>"Followers"</dt>
                    <dd>{render_count(followers)}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Following"</dt>
                    <dd>{render_count(follows)}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Posts"</dt>
                    <dd>{render_count(posts)}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Account age"</dt>
                    <dd>{render_age(age)}</dd>
                </div>
            </dl>
            <div class="network-panel__badges">
                {new_account.then(|| view! {
                    <span class="network-panel__badge network-panel__badge--new" role="status">
                        "New account (≤ 7 days)"
                    </span>
                })}
                {is_labeler.then(|| view! {
                    <span class="network-panel__badge network-panel__badge--labeler" role="status">
                        "Labeler account"
                    </span>
                })}
                {pinned.as_deref().and_then(at_uri_to_bsky_post_url).map(|url| view! {
                    <a
                        class="network-panel__badge network-panel__badge--pinned"
                        href=url
                        target="_blank"
                        rel="noreferrer"
                    >
                        "Pinned post"
                    </a>
                })}
            </div>
            // Third-party labels are NOT rendered here — they live in
            // the dedicated `ThirdPartyLabelsPanel` mounted below the
            // subject panel. Rendering them in both places duplicated
            // the panel surface and confused moderators about which
            // copy was authoritative.
        </section>
    }
    .into_any()
}

/// Follow-graph section — recent followers, recent follows,
/// mutual count.
#[cfg(target_arch = "wasm32")]
fn render_follow_graph_section(graph: &FollowGraph, quality: &SignalQuality) -> AnyView {
    if !quality.follow_graph_loaded {
        return view! {
            <section class="network-panel__follow-graph">
                <h3 class="network-panel__subtitle">"Follow graph"</h3>
                <p class="network-panel__section-unavailable" role="status">
                    "Follow-graph signal unavailable (upstream fetch failed)."
                </p>
            </section>
        }
        .into_any();
    }
    let mutual = graph.mutual_count;
    let followers = graph.recent_followers.len();
    let follows = graph.recent_follows.len();

    view! {
        <section class="network-panel__follow-graph">
            <h3 class="network-panel__subtitle">"Engagement"</h3>
            <dl class="network-panel__engagement-stats">
                <div class="network-panel__stat">
                    <dt>"Mutual follows (recent)"</dt>
                    <dd>{mutual}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Recent followers sampled"</dt>
                    <dd>{followers}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Recent follows sampled"</dt>
                    <dd>{follows}</dd>
                </div>
            </dl>
        </section>
    }
    .into_any()
}

/// Activity-pattern section — replaces the recent-followers /
/// recent-follows lists with derived signals a moderator can read
/// at a glance.
///
/// Renders:
///   * a one-line summary (total posts seen, posts in 7d/30d,
///     time since latest post)
///   * a 30-day daily-post histogram (sparkline of bars)
///   * a 24-hour hour-of-day chart
///   * a 7-day weekday chart
#[cfg(target_arch = "wasm32")]
fn render_activity_pattern_section(pattern: &ActivityPattern) -> AnyView {
    if pattern.total_posts_seen == 0 {
        return view! {
            <section class="network-panel__activity">
                <h3 class="network-panel__subtitle">"Activity pattern"</h3>
                <p class="network-panel__section-empty" role="status">
                    "No author-feed posts observed for this account in the AppView walk window."
                </p>
            </section>
        }
        .into_any();
    }

    let total = pattern.total_posts_seen;
    let last_7d = pattern.posts_last_7d;
    let last_30d = pattern.posts_last_30d;
    let latest = pattern.latest_post_at.clone();
    let daily = pattern.posts_per_day_30d.clone();
    let daily_slice = daily.clone();
    let hourly = pattern.posts_per_hour_utc;
    let weekday = pattern.posts_per_weekday;

    view! {
        <section class="network-panel__activity">
            <h3 class="network-panel__subtitle">"Activity pattern"</h3>
            <dl class="network-panel__activity-stats">
                <div class="network-panel__stat">
                    <dt>"Posts last 7 days"</dt>
                    <dd>{last_7d}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Posts last 30 days"</dt>
                    <dd>{last_30d}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Posts in walk window"</dt>
                    <dd>{total}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Latest post"</dt>
                    <dd>{format_latest_post(latest.as_deref())}</dd>
                </div>
            </dl>
            <div class="network-panel__activity-chart">
                <h4 class="network-panel__chart-title">
                    "Posts per day (last 30 days, UTC)"
                </h4>
                {render_daily_histogram(&daily_slice)}
            </div>
            <div class="network-panel__activity-chart">
                <h4 class="network-panel__chart-title">
                    "Posts by hour (UTC)"
                </h4>
                {render_hourly_chart(hourly)}
            </div>
            <div class="network-panel__activity-chart">
                <h4 class="network-panel__chart-title">
                    "Posts by weekday"
                </h4>
                {render_weekday_chart(weekday)}
            </div>
        </section>
    }
    .into_any()
}

/// Render the 30-day daily-post histogram. The chart is two
/// stacked grid rows that share the same `grid-template-columns`:
/// the upper row is the bars (heights set inline as a percentage of
/// the max-day count); the lower row is the x-axis labels at fixed
/// positions so the moderator can read calendar anchors without
/// hovering.
#[cfg(target_arch = "wasm32")]
fn render_daily_histogram(days: &[DailyPostCount]) -> AnyView {
    if days.is_empty() {
        return view! {
            <p class="network-panel__chart-empty" role="status">
                "No daily activity data in the walk window."
            </p>
        }
        .into_any();
    }
    let max = days.iter().map(|d| d.count).max().unwrap_or(0).max(1);
    // Label every 5th day so the axis carries 6 anchors total
    // across the 30-day window. The remaining cells render empty
    // so the grid alignment with the bar row is preserved.
    let len = days.len();
    let last_idx = len.saturating_sub(1);
    let label_positions: Vec<usize> = (0..len).filter(|i| i % 5 == 0 || *i == last_idx).collect();
    let bar_view = days
        .iter()
        .map(|d| {
            let pct = (d.count * 100) / max;
            let label = format!("{}: {} posts", d.date, d.count);
            let style = format!("height: {pct}%");
            view! {
                <li class="network-panel__bar" title=label>
                    <span class="network-panel__bar-fill" style=style></span>
                </li>
            }
            .into_any()
        })
        .collect_view()
        .into_any();
    let axis_view = days
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let show = label_positions.contains(&i);
            // The label is the "MM-DD" tail of the YYYY-MM-DD date
            // so the axis fits at small widths; the full ISO date
            // is on the bar's `title` for hover.
            let short = d.date.get(5..).unwrap_or(d.date.as_str()).to_owned();
            view! {
                <li class="network-panel__axis-cell">
                    {show.then(|| view! {
                        <span class="network-panel__axis-label">{short}</span>
                    })}
                </li>
            }
            .into_any()
        })
        .collect_view()
        .into_any();
    view! {
        <div class="network-panel__chart-track">
            <ol class="network-panel__bar-row network-panel__bar-row--daily" role="img"
                aria-label="Daily post count for the last 30 days">
                {bar_view}
            </ol>
            <ol class="network-panel__axis-row network-panel__axis-row--daily" aria-hidden="true">
                {axis_view}
            </ol>
        </div>
    }
    .into_any()
}

/// Render the 24-hour-of-day chart. Axis labels every 4 hours
/// (00 / 04 / 08 / 12 / 16 / 20) so the moderator can spot
/// time-zone-correlated bursts (e.g., a flat 24h cadence is a
/// bot signal; a 6h-quiet stretch is sleep).
#[cfg(target_arch = "wasm32")]
fn render_hourly_chart(hours: [i64; 24]) -> AnyView {
    let max = hours.iter().copied().max().unwrap_or(0).max(1);
    let bar_view = (0..24_usize)
        .map(|h| {
            let count = hours[h];
            let pct = (count * 100) / max;
            let label = format!("{h:02}:00 UTC: {count} posts");
            let style = format!("height: {pct}%");
            view! {
                <li class="network-panel__bar" title=label>
                    <span class="network-panel__bar-fill" style=style></span>
                </li>
            }
            .into_any()
        })
        .collect_view()
        .into_any();
    let axis_view = (0..24_usize)
        .map(|h| {
            let show = matches!(h, 0 | 4 | 8 | 12 | 16 | 20);
            view! {
                <li class="network-panel__axis-cell">
                    {show.then(|| view! {
                        <span class="network-panel__axis-label">{format!("{h:02}")}</span>
                    })}
                </li>
            }
            .into_any()
        })
        .collect_view()
        .into_any();
    view! {
        <div class="network-panel__chart-track">
            <ol class="network-panel__bar-row network-panel__bar-row--hourly" role="img"
                aria-label="Posts by hour of day, UTC">
                {bar_view}
            </ol>
            <ol class="network-panel__axis-row network-panel__axis-row--hourly" aria-hidden="true">
                {axis_view}
            </ol>
        </div>
    }
    .into_any()
}

/// Render the 7-day weekday chart with all 7 day-name labels
/// visible on the axis below the bars.
#[cfg(target_arch = "wasm32")]
fn render_weekday_chart(days: [i64; 7]) -> AnyView {
    let max = days.iter().copied().max().unwrap_or(0).max(1);
    let labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let bar_view = (0..7_usize)
        .map(|d| {
            let count = days[d];
            let pct = (count * 100) / max;
            let style = format!("height: {pct}%");
            let title = format!("{}: {count} posts", labels[d]);
            view! {
                <li class="network-panel__bar" title=title>
                    <span class="network-panel__bar-fill" style=style></span>
                </li>
            }
            .into_any()
        })
        .collect_view()
        .into_any();
    let axis_view = labels
        .iter()
        .map(|name| {
            view! {
                <li class="network-panel__axis-cell">
                    <span class="network-panel__axis-label">{*name}</span>
                </li>
            }
            .into_any()
        })
        .collect_view()
        .into_any();
    view! {
        <div class="network-panel__chart-track">
            <ol class="network-panel__bar-row network-panel__bar-row--weekday" role="img"
                aria-label="Posts by day of week">
                {bar_view}
            </ol>
            <ol class="network-panel__axis-row network-panel__axis-row--weekday" aria-hidden="true">
                {axis_view}
            </ol>
        </div>
    }
    .into_any()
}

/// Format the "latest post" timestamp as a relative-time string.
/// Falls back to the raw RFC 3339 string if parsing fails, or to
/// `"never"` when no post has been observed.
#[cfg(target_arch = "wasm32")]
fn format_latest_post(rfc3339: Option<&str>) -> String {
    let Some(raw) = rfc3339 else {
        return "never".to_owned();
    };
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(raw) else {
        return raw.to_owned();
    };
    let now = chrono::Utc::now();
    let delta = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
    let mins = delta.num_minutes();
    if mins < 1 {
        "just now".to_owned()
    } else if mins < 60 {
        format!("{mins} min ago")
    } else if mins < 24 * 60 {
        format!("{}h ago", delta.num_hours())
    } else if delta.num_days() < 30 {
        format!("{}d ago", delta.num_days())
    } else {
        // Beyond 30 days fall back to the raw date — the relative
        // form gets imprecise.
        parsed.format("%Y-%m-%d").to_string()
    }
}

/// Reply-graph section — distinct outgoing / incoming partner
/// counts plus one named top partner per direction. The full actor
/// lists ([`ReplyGraph::recent_replies_to`] / `recent_repliers`)
/// are still on the wire so the cohort section can consume them;
/// this section deliberately shows aggregates instead, to keep the
/// case-view compact.
#[cfg(target_arch = "wasm32")]
fn render_reply_graph_section(graph: &ReplyGraph, quality: &SignalQuality) -> AnyView {
    if !quality.reply_graph_loaded {
        return view! {
            <section class="network-panel__reply-graph">
                <h3 class="network-panel__subtitle">"Reply patterns"</h3>
                <p class="network-panel__section-unavailable" role="status">
                    "Reply-graph signal unavailable (upstream fetch failed)."
                </p>
            </section>
        }
        .into_any();
    }
    let out_partners = graph.recent_replies_to.len();
    let in_partners = graph.recent_repliers.len();
    let top_out = graph.recent_replies_to.first().cloned();
    let top_in = graph.recent_repliers.first().cloned();

    if out_partners == 0 && in_partners == 0 {
        return view! {
            <section class="network-panel__reply-graph">
                <h3 class="network-panel__subtitle">"Reply patterns"</h3>
                <p class="network-panel__section-empty" role="status">
                    "No reply activity observed in the AppView walk window."
                </p>
            </section>
        }
        .into_any();
    }

    view! {
        <section class="network-panel__reply-graph">
            <h3 class="network-panel__subtitle">"Reply patterns"</h3>
            <dl class="network-panel__reply-stats">
                <div class="network-panel__stat">
                    <dt>"Distinct accounts subject replies to"</dt>
                    <dd>{out_partners}</dd>
                </div>
                <div class="network-panel__stat">
                    <dt>"Distinct accounts replying to subject"</dt>
                    <dd>{in_partners}</dd>
                </div>
                {top_out.map(|actor| view! {
                    <div class="network-panel__stat network-panel__stat--full">
                        <dt>"Most-recent outgoing partner"</dt>
                        <dd>{render_actor_inline(&actor)}</dd>
                    </div>
                })}
                {top_in.map(|actor| view! {
                    <div class="network-panel__stat network-panel__stat--full">
                        <dt>"Most-recent incoming partner"</dt>
                        <dd>{render_actor_inline(&actor)}</dd>
                    </div>
                })}
            </dl>
        </section>
    }
    .into_any()
}

/// One-line actor display used inline in the reply-graph stats —
/// display name + handle when known, with a fallback to the bare
/// DID. Avoids pulling in the heavier `render_actor_list` shape
/// for what is now a single-row affordance.
#[cfg(target_arch = "wasm32")]
fn render_actor_inline(actor: &NetworkActor) -> AnyView {
    let primary = actor
        .display_name
        .clone()
        .or_else(|| actor.handle.clone())
        .unwrap_or_else(|| actor.did.clone());
    let secondary = actor.handle.clone();
    view! {
        <span class="network-panel__actor-inline">
            <span class="network-panel__actor-name">{primary}</span>
            {secondary.map(|h| view! {
                <span class="network-panel__actor-handle">"@"{h}</span>
            })}
        </span>
    }
    .into_any()
}

/// Cohort section — mutual-follow overlap + top interaction
/// partners.
#[cfg(target_arch = "wasm32")]
fn render_cohort_section(cohort: &CohortSignals) -> AnyView {
    let mutual_overlap = cohort.mutual_follow_overlap.clone();
    let interaction_partners = cohort.top_interaction_partners.clone();

    if mutual_overlap.is_empty() && interaction_partners.is_empty() {
        return view! {
            <section class="network-panel__cohort">
                <h3 class="network-panel__subtitle">"Cohort"</h3>
                <p class="network-panel__cohort-empty" role="status">
                    "No mutual-follow or interaction overlap detected in the sampled set."
                </p>
            </section>
        }
        .into_any();
    }

    view! {
        <section class="network-panel__cohort">
            <h3 class="network-panel__subtitle">"Cohort"</h3>
            <div class="network-panel__columns">
                <div class="network-panel__column">
                    <h4 class="network-panel__column-title">
                        "Mutual follows ("{mutual_overlap.len()}")"
                    </h4>
                    {render_actor_list(mutual_overlap)}
                </div>
                <div class="network-panel__column">
                    <h4 class="network-panel__column-title">
                        "Top interaction partners ("{interaction_partners.len()}")"
                    </h4>
                    {render_actor_list(interaction_partners)}
                </div>
            </div>
        </section>
    }
    .into_any()
}

/// Shared-image cluster section — the cross-subject CID match
/// signal. Renders the count of unique image CIDs the subject
/// embedded recently, plus the list of OTHER subjects that share
/// any of those CIDs.
#[cfg(target_arch = "wasm32")]
fn render_shared_images_section(signals: &SharedImageSignals, quality: &SignalQuality) -> AnyView {
    if !quality.shared_images_loaded {
        return view! {
            <section class="network-panel__shared-images">
                <h3 class="network-panel__subtitle">"Shared images"</h3>
                <p class="network-panel__section-unavailable" role="status">
                    "Shared-image signal unavailable (upstream fetch failed)."
                </p>
            </section>
        }
        .into_any();
    }
    let cid_count = signals.recent_image_cids.len();
    let matched = signals.matched_subjects.clone();

    if cid_count == 0 {
        return view! {
            <section class="network-panel__shared-images">
                <h3 class="network-panel__subtitle">"Shared images"</h3>
                <p class="network-panel__shared-images-empty" role="status">
                    "Subject has not embedded any images in recent posts."
                </p>
            </section>
        }
        .into_any();
    }

    view! {
        <section class="network-panel__shared-images">
            <h3 class="network-panel__subtitle">"Shared images"</h3>
            <p class="network-panel__shared-images-summary" role="status">
                <strong>{cid_count}</strong>" image"{if cid_count == 1 { "" } else { "s" }}
                " in recent posts; "<strong>{matched.len()}</strong>" matching subject"
                {if matched.len() == 1 { "" } else { "s" }}" in Polaris."
            </p>
            {(!matched.is_empty()).then(|| view! {
                <ul class="network-panel__matched-list">
                    {render_matched_subject_list(matched)}
                </ul>
            })}
        </section>
    }
    .into_any()
}

// ── Render helpers ───────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
fn render_count(n: Option<i64>) -> AnyView {
    match n {
        Some(value) => view! { <span class="network-panel__count">{value}</span> }.into_any(),
        None => {
            view! { <span class="network-panel__count network-panel__count--unknown">"—"</span> }
                .into_any()
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn render_age(days: Option<i64>) -> AnyView {
    match days {
        Some(d) if d < 1 => view! {
            <span class="network-panel__age network-panel__age--very-new">"< 1 day"</span>
        }
        .into_any(),
        Some(d) if d <= 7 => view! {
            <span class="network-panel__age network-panel__age--new">{d}" days"</span>
        }
        .into_any(),
        Some(d) if d < 365 => view! {
            <span class="network-panel__age">{d}" days"</span>
        }
        .into_any(),
        Some(d) => view! {
            <span class="network-panel__age">{d / 365}" years"</span>
        }
        .into_any(),
        None => view! { <span class="network-panel__age">"unknown"</span> }.into_any(),
    }
}

#[cfg(target_arch = "wasm32")]
fn render_actor_list(actors: Vec<NetworkActor>) -> AnyView {
    if actors.is_empty() {
        return view! {
            <p class="network-panel__empty-actor-list">"None"</p>
        }
        .into_any();
    }
    view! {
        <ul class="network-panel__actor-list">
            {actors.into_iter().map(render_actor_row).collect_view()}
        </ul>
    }
    .into_any()
}

#[cfg(target_arch = "wasm32")]
fn render_actor_row(actor: NetworkActor) -> AnyView {
    let display = actor
        .display_name
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| actor.handle.clone())
        .unwrap_or_else(|| actor.did.clone());
    let handle_label = actor.handle.clone().unwrap_or_else(|| actor.did.clone());
    let profile_href = match actor.handle.as_ref() {
        Some(handle) => format!("https://bsky.app/profile/{handle}"),
        None => format!("https://bsky.app/profile/{}", actor.did),
    };
    // Per-row pivot state: `Idle` → click → `Resolving` → on success
    // navigate (no surface change), on failure → `Failed(msg)`. The
    // signal is per-row because each actor's pivot is independent.
    let (pivot_state, set_pivot_state) = signal(PivotState::Idle);
    let pivot_did = actor.did.clone();
    let pivot_did_for_button = pivot_did.clone();
    let on_pivot = move |_| {
        let did = pivot_did_for_button.clone();
        set_pivot_state.set(PivotState::Resolving);
        spawn_pivot_lookup(did, set_pivot_state);
    };
    view! {
        <li class="network-panel__actor-row">
            {actor.avatar.map(|src| view! {
                <img
                    class="network-panel__actor-avatar"
                    src=src
                    alt=""
                    loading="lazy"
                />
            })}
            <a
                class="network-panel__actor-link"
                href=profile_href
                target="_blank"
                rel="noreferrer"
                title=actor.did.clone()
            >
                <span class="network-panel__actor-name">{display}</span>
                <span class="network-panel__actor-handle">{handle_label}</span>
            </a>
            <button
                type="button"
                class="network-panel__actor-pivot"
                aria-label=format!("Open Polaris case for {pivot_did}")
                title="Open Polaris case for this actor"
                disabled=move || matches!(pivot_state.get(), PivotState::Resolving)
                on:click=on_pivot
            >
                {move || match pivot_state.get() {
                    PivotState::Idle => "→ case".to_owned(),
                    PivotState::Resolving => "resolving…".to_owned(),
                    PivotState::Failed(msg) => format!("failed: {msg}"),
                }}
            </button>
        </li>
    }
    .into_any()
}

/// Per-row state for the actor-pivot button. Only exists on wasm
/// because the pivot lookup itself is wasm-gated; on native there
/// is no caller and no state to track.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
enum PivotState {
    /// No pivot in flight — button shows the "→ case" affordance.
    Idle,
    /// Pivot lookup running; button is disabled.
    Resolving,
    /// Lookup failed; button displays the error verbatim so the
    /// moderator can decide whether to retry.
    Failed(String),
}

/// Resolve `did` to a Polaris subject id and navigate the case view.
///
/// Calls `POST /api/subjects/lookup` (the same endpoint the command
/// palette uses for moderator-pasted identifiers); on success the
/// returned `subject_id` is pushed to the router so the case view
/// mounts for the pivoted actor without a full reload. On failure
/// the button surfaces the error inline; the user can retry or fall
/// back to the external Bluesky link beside the button.
#[allow(
    unused_variables,
    reason = "did + setter only consumed on the wasm path; native test builds use them via the \
              gate below"
)]
#[cfg(target_arch = "wasm32")]
fn spawn_pivot_lookup(did: String, set_state: WriteSignal<PivotState>) {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api_client::{PolarisApiClient as _, default_client};
        use leptos_router::hooks::use_navigate;
        let navigate = use_navigate();
        leptos::task::spawn_local(async move {
            let outcome = async {
                let client = default_client("").map_err(|e| e.to_string())?;
                let resp = client
                    .lookup_subject(&did)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok::<String, String>(resp.subject_id)
            }
            .await;
            match outcome {
                Ok(subject_id) => {
                    navigate(
                        &format!("/cases/{subject_id}"),
                        leptos_router::NavigateOptions::default(),
                    );
                }
                Err(msg) => {
                    set_state.set(PivotState::Failed(msg));
                }
            }
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native type-check builds: no backend, no router. Leave
        // the state at Resolving so the button stays disabled —
        // the test harness only exercises the dispatch shape.
        let _ = (did, set_state);
    }
}

/// Convert an ATProto post AT-URI to the browser-navigable Bluesky
/// web URL the moderator's browser can actually open.
///
/// Browsers refuse to navigate to bare `at://` hrefs (the click
/// produces `about:blank#blocked` because no protocol handler is
/// registered), so the pinned-post badge must rewrite the URI to
/// the public Bluesky web form before rendering the `<a href>`.
///
/// # AT-URI shape
///
/// `at://<did>/<collection>/<rkey>` — e.g.
/// `at://did:plc:abc123/app.bsky.feed.post/3kfoo`.
///
/// # Web URL shape
///
/// `https://bsky.app/profile/<did>/post/<rkey>` — bsky.app resolves
/// `<did>` as either a `did:plc:…` literal or a handle (we always
/// pass the DID form because the AT-URI already carries it; passing
/// the handle would require a separate resolution step).
///
/// Returns `None` when:
///   * the input is not an `at://` URI,
///   * the URI's collection segment is not `app.bsky.feed.post`
///     (other collections — lists, feeds, profiles — have different
///     web-URL shapes and are not in scope for the pinned-post
///     affordance),
///   * the URI is malformed (missing rkey, missing did).
#[cfg(target_arch = "wasm32")]
fn at_uri_to_bsky_post_url(at_uri: &str) -> Option<String> {
    let rest = at_uri.strip_prefix("at://")?;
    // Expected shape after the prefix: `<did>/<collection>/<rkey>`.
    let mut parts = rest.splitn(3, '/');
    let did = parts.next()?;
    let collection = parts.next()?;
    let rkey = parts.next()?;
    if did.is_empty() || rkey.is_empty() {
        return None;
    }
    if collection != "app.bsky.feed.post" {
        return None;
    }
    Some(format!("https://bsky.app/profile/{did}/post/{rkey}"))
}

#[cfg(target_arch = "wasm32")]
fn render_matched_subject_list(matches: Vec<MatchedSubject>) -> AnyView {
    matches
        .into_iter()
        .map(|m| {
            let href = format!("/cases/{}", m.subject_id);
            let did_label = m.did.clone().unwrap_or_else(|| m.subject_id.clone());
            let shared_count = m.shared_cids.len();
            view! {
                <li class="network-panel__matched-row">
                    <a class="network-panel__matched-link" href=href>
                        {did_label}
                    </a>
                    <span class="network-panel__matched-count">
                        "("{shared_count}" shared image"
                        {if shared_count == 1 { "" } else { "s" }}")"
                    </span>
                </li>
            }
            .into_any()
        })
        .collect_view()
        .into_any()
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(all(test, target_arch = "wasm32"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    fn sample_actor(did: &str, handle: &str) -> NetworkActor {
        NetworkActor {
            did: did.to_owned(),
            handle: Some(handle.to_owned()),
            display_name: None,
            avatar: None,
        }
    }

    #[test]
    fn render_count_some_uses_number() {
        // Pure function via the AnyView return — we exercise the
        // dispatch shape rather than the rendered markup (Leptos
        // view! cannot serialise without a runtime). Calling the
        // helper without panicking is the contract here.
        let _ = render_count(Some(42));
        let _ = render_count(None);
    }

    #[test]
    fn render_age_buckets_dispatch() {
        // Each bucket must complete without panicking.
        let _ = render_age(Some(0));
        let _ = render_age(Some(5));
        let _ = render_age(Some(100));
        let _ = render_age(Some(400));
        let _ = render_age(None);
    }

    #[test]
    fn render_actor_list_empty_branch() {
        let _ = render_actor_list(Vec::new());
    }

    #[test]
    fn render_actor_list_populated_branch() {
        let actors = vec![
            sample_actor("did:plc:a", "a.bsky.social"),
            sample_actor("did:plc:b", "b.bsky.social"),
        ];
        let _ = render_actor_list(actors);
    }

    #[test]
    fn at_uri_to_bsky_post_url_rewrites_canonical_shape() {
        // The pinned-post helper must convert the AppView's
        // at://did/app.bsky.feed.post/<rkey> shape to the
        // browser-navigable https://bsky.app/profile/<did>/post/<rkey>
        // form. The DID is preserved verbatim — bsky.app resolves
        // it identically.
        let url = at_uri_to_bsky_post_url("at://did:plc:abc123/app.bsky.feed.post/3kfoo");
        assert_eq!(
            url.as_deref(),
            Some("https://bsky.app/profile/did:plc:abc123/post/3kfoo"),
        );
    }

    #[test]
    fn at_uri_to_bsky_post_url_rejects_non_atproto_scheme() {
        // Anything that isn't an at:// URI must return None so the
        // pinned badge stays unrendered rather than producing a
        // broken link.
        assert!(at_uri_to_bsky_post_url("https://example.com/post").is_none());
        assert!(at_uri_to_bsky_post_url("not a uri").is_none());
        assert!(at_uri_to_bsky_post_url("").is_none());
    }

    #[test]
    fn at_uri_to_bsky_post_url_rejects_non_post_collections() {
        // Only app.bsky.feed.post AT-URIs have a corresponding
        // https://bsky.app/profile/<did>/post/<rkey> form. List /
        // feed / actor URIs would silently break if mapped onto
        // the same template, so the helper returns None.
        assert!(at_uri_to_bsky_post_url("at://did:plc:abc/app.bsky.graph.list/3xyz").is_none());
        assert!(at_uri_to_bsky_post_url("at://did:plc:abc/app.bsky.actor.profile/self").is_none());
    }

    #[test]
    fn at_uri_to_bsky_post_url_rejects_missing_segments() {
        assert!(at_uri_to_bsky_post_url("at://").is_none());
        assert!(at_uri_to_bsky_post_url("at://did:plc:abc").is_none());
        assert!(at_uri_to_bsky_post_url("at://did:plc:abc/app.bsky.feed.post").is_none());
        // Missing rkey (trailing slash with empty segment).
        assert!(at_uri_to_bsky_post_url("at://did:plc:abc/app.bsky.feed.post/").is_none());
    }

    #[test]
    fn fetch_state_variants_constructable() {
        // The enum is constructed only inside the wasm-gated
        // spawn_local in production. The test asserts that the
        // shape compiles + dispatches across all three variants —
        // a regression here would catch a future refactor that
        // accidentally drops one of the arms.
        //
        // `matches!` confirms each constructed value has the
        // expected variant. Plain `let _l = …` would trip
        // `clippy::no_effect_underscore_binding` because the
        // binding produces no observable effect.
        let l = FetchState::Loading;
        assert!(matches!(l, FetchState::Loading));
        let r = FetchState::Ready(NetworkContext {
            did: "did:plc:x".into(),
            handle: None,
            display_name: None,
            description: None,
            avatar: None,
            followers_count: None,
            follows_count: None,
            posts_count: None,
            created_at: None,
            indexed_at: None,
            account_age_days: None,
            labels: Vec::new(),
            pinned_post_uri: None,
            pinned_post_cid: None,
            is_labeler: false,
            follow_graph: FollowGraph::default(),
            activity_pattern: ActivityPattern::default(),
            reply_graph: ReplyGraph::default(),
            cohort: CohortSignals::default(),
            shared_images: SharedImageSignals::default(),
            source_url: "url".into(),
            signal_quality: SignalQuality::default(),
        });
        assert!(matches!(r, FetchState::Ready(_)));
        let f = FetchState::Failed("boom".to_owned());
        assert!(matches!(f, FetchState::Failed(_)));
    }
}
