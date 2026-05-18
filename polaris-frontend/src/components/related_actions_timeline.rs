//! `RelatedActionsTimeline` — every Polaris moderation action ever
//! taken against ANY subject owned by the current case-view's DID.
//!
//! Issue #3 (case-view aggregation): the case view's primary
//! `history` field surfaces actions against the exact subject row a
//! moderator is looking at. For account subjects, that misses every
//! action Polaris ever took against any of the subject's posts; for
//! post subjects, it misses actions on the author's account and on
//! their other posts.
//!
//! The backend's `build_related_actions` does one SQL pass joining
//! `actions` to `subjects` on the shared DID; this component renders
//! the result as a timeline with target-context badges so a
//! moderator can tell at a glance which row each action targeted
//! ("Label on post @rkey", "Takedown on related account row") and
//! click through to that subject's case view.

use leptos::prelude::*;

use crate::api_client::dto::RelatedAction;

/// Render the related-actions timeline. Rendered as a sibling to the
/// primary `HistoryTimeline` so the moderator sees the complete
/// audit trail across every related row.
#[component]
#[allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "Leptos #[component] macros accept props by value as the framework convention"
)]
pub fn RelatedActionsTimeline(
    /// The set of actions targeting other subjects owned by the same
    /// DID. Empty Vec → renders an honest "no other actions" status
    /// row rather than an empty container.
    actions: Vec<RelatedAction>,
) -> impl IntoView {
    let count = actions.len();
    if count == 0 {
        return view! {
            <section class="related-actions-timeline" role="region"
                     aria-label="Other actions on this user">
                <h3 class="related-actions-timeline__title">
                    "Other actions on this user"
                </h3>
                <p class="related-actions-timeline__empty" role="status">
                    "No other Polaris actions have been taken against this user's \
                     account or any of their posts."
                </p>
            </section>
        }
        .into_any();
    }

    let rows: Vec<_> = actions.into_iter().map(render_row).collect();

    view! {
        <section class="related-actions-timeline" role="region"
                 aria-label="Other actions on this user">
            <header class="related-actions-timeline__header">
                <h3 class="related-actions-timeline__title">
                    "Other actions on this user"
                </h3>
                <p class="related-actions-timeline__count" role="status">
                    {count}" action(s) on related rows (account + posts \
                     under the same DID)."
                </p>
            </header>
            <ul class="related-actions-timeline__list" role="list">
                {rows}
            </ul>
        </section>
    }
    .into_any()
}

/// Render one `RelatedAction` row.
fn render_row(entry: RelatedAction) -> AnyView {
    let RelatedAction {
        action,
        target_subject_id,
        target_subject_kind,
        target_subject_uri,
    } = entry;

    let kind = format!("{:?}", action.kind);
    let when = action.created_at.to_rfc3339();
    let reasoning = action.reasoning.clone();
    let target_label = format_target_label(&target_subject_kind, target_subject_uri.as_deref());
    let case_href = format!("/cases/{}", target_subject_id.as_uuid());

    view! {
        <li class="related-actions-timeline__item">
            <header class="related-actions-timeline__item-header">
                <span class="related-actions-timeline__kind">{kind}</span>
                <a class="related-actions-timeline__target"
                   href=case_href
                   title="Open the related subject's case view">
                    {target_label}
                </a>
                <time class="related-actions-timeline__when">{when}</time>
            </header>
            <p class="related-actions-timeline__reasoning">{reasoning}</p>
        </li>
    }
    .into_any()
}

/// Compose a short human-readable label for the related subject's
/// row. Distinguishes account-kind from post-kind rows so the
/// moderator's eye separates "another action on the same account
/// row" from "an action on a post by this user."
fn format_target_label(kind: &str, uri: Option<&str>) -> String {
    match kind {
        "account" => "related account row".to_owned(),
        "post" => match uri.and_then(extract_post_rkey) {
            Some(rkey) => format!("post {rkey}"),
            None => "post".to_owned(),
        },
        "list" => "list".to_owned(),
        "feed" => "feed".to_owned(),
        other => format!("{other}-subject"),
    }
}

/// Pull the `rkey` (the last AT-URI segment) from an
/// `at://did/<collection>/<rkey>` AT-URI. Returns `None` on any
/// shape mismatch.
fn extract_post_rkey(at_uri: &str) -> Option<String> {
    let rest = at_uri.strip_prefix("at://")?;
    let rkey = rest.rsplit('/').next()?;
    if rkey.is_empty() {
        None
    } else {
        Some(rkey.to_owned())
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

    #[test]
    fn format_target_label_account_kind_is_unambiguous() {
        assert_eq!(format_target_label("account", None), "related account row");
    }

    #[test]
    fn format_target_label_post_kind_extracts_rkey() {
        assert_eq!(
            format_target_label("post", Some("at://did:plc:abc/app.bsky.feed.post/3kfoo"),),
            "post 3kfoo",
        );
    }

    #[test]
    fn format_target_label_post_kind_without_uri_falls_back_honestly() {
        // No URI to extract from — show "post" rather than fabricate
        // an identifier.
        assert_eq!(format_target_label("post", None), "post");
    }

    #[test]
    fn format_target_label_unknown_kind_is_explicit() {
        // Don't drop unknown kinds silently; surface what we got.
        assert_eq!(
            format_target_label("starterpack", None),
            "starterpack-subject",
        );
    }

    #[test]
    fn extract_post_rkey_pulls_trailing_segment() {
        assert_eq!(
            extract_post_rkey("at://did:plc:x/app.bsky.feed.post/3kfoo").as_deref(),
            Some("3kfoo"),
        );
    }

    #[test]
    fn extract_post_rkey_rejects_non_atproto() {
        assert!(extract_post_rkey("https://example.com/x").is_none());
        assert!(extract_post_rkey("").is_none());
    }

    #[test]
    fn extract_post_rkey_rejects_empty_trailing_segment() {
        assert!(extract_post_rkey("at://did:plc:x/app.bsky.feed.post/").is_none());
    }
}
