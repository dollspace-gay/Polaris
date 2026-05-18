//! `GET /api/cases/{subject_id}/network-context` — M2 case-view
//! network-context panel (issue #97).
//!
//! Surfaces the four signal categories the moderator's case view
//! consumes when deciding on a subject:
//!
//! 1. **Profile signals** — followers / follows / posts counts,
//!    account age, applied labels (from other labelers), pinned
//!    post, `associated.labeler` flag.
//! 2. **Follow graph** — most-recent followers, most-recent
//!    follows, mutual-follow intersection. Mutual-follow size is
//!    the "this account is embedded in a real social network"
//!    signal; near-zero mutual follow on a 7000-follow account is
//!    the spam-bot shape.
//! 3. **Reply graph** — who the subject replies to (extracted
//!    from `getAuthorFeed`) and who replies to the subject's
//!    recent posts (parallel `getPostThread` walks). The
//!    "who-replies-to" direction is the brigade-detection signal
//!    when one account shows up across many subjects.
//! 4. **Cohort signals** — top mutual-follow overlap and top
//!    interaction partners (intersection of mutual follows ∩
//!    reply graph). Visualises the subject's tight cluster.
//! 5. **Shared-image clusters** — for every blob CID the subject
//!    has embedded (via `getAuthorFeed`'s `embed.images` field),
//!    upsert into `subject_image_blobs` and query for OTHER
//!    subjects that share any of those CIDs. Identical CIDs across
//!    distinct subjects = identical bytes = duplicate content;
//!    the canonical signal for re-posted spam imagery and
//!    coordinated meme campaigns.
//!
//! All signals derive from public AppView endpoints
//! (`public.api.bsky.app`) plus Polaris's own
//! `subject_image_blobs` table. No firehose ingest required; the
//! data is lazily populated on case-view load (case-view is the
//! natural read-and-write point for per-subject network context).
//!
//! # Performance
//!
//! Four AppView fetches run in parallel via `tokio::join!`. Each
//! is timeout-bounded at 8 seconds. The reply-graph reverse walk
//! parallelises `getPostThread` calls across up to 8 of the
//! subject's most-recent posts so the case-view load completes
//! in ~1-2 seconds even with all signals enabled.
//!
//! # Partial-failure semantics
//!
//! Each of the parallel fetches is independent. A failure in one
//! fetch does NOT fail the handler; instead the affected section
//! of the response is populated with empty/None values and the
//! frontend renders an inline "this signal unavailable" hint.
//! The moderator should always see *some* context even when one
//! upstream is degraded.
//!
//! # Authorization
//!
//! Routed through the authed subtree: every moderator role gets
//! the panel. The data is public, but the auth gate keeps Polaris
//! from being abused as a public proxy.

use std::collections::HashSet;
use std::time::Duration;

use axum::Json;
use axum::extract::{Extension, Path, State};
use polaris_types::SubjectId;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;

// ── Wire-shape DTOs ──────────────────────────────────────────────────

/// The full network-context response delivered to the case-view
/// panel. Every sub-field is independently populated; an empty
/// section is the documented "this signal unavailable" state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContextResponse {
    /// Subject DID. Echoed so the frontend can render a copy
    /// affordance without re-querying.
    pub did: String,
    /// Subject handle. `None` when AppView returns
    /// `handle.invalid` or empty.
    pub handle: Option<String>,
    /// User-edited display name. `None` when empty.
    pub display_name: Option<String>,
    /// Self-authored bio. `None` when empty.
    pub description: Option<String>,
    /// CDN URL of the avatar image, if any.
    pub avatar: Option<String>,
    /// Count of accounts following this subject.
    pub followers_count: Option<i64>,
    /// Count of accounts this subject follows.
    pub follows_count: Option<i64>,
    /// Count of posts the subject has published.
    pub posts_count: Option<i64>,
    /// Account creation timestamp (RFC-3339).
    pub created_at: Option<String>,
    /// Last AppView re-index timestamp.
    pub indexed_at: Option<String>,
    /// Days between `created_at` and `now()`. `None` if the
    /// timestamp is missing or unparseable.
    pub account_age_days: Option<i64>,
    /// Labels applied to this subject by labelers OTHER than
    /// Polaris itself.
    pub labels: Vec<NetworkContextLabel>,
    /// Pinned-post AT-URI when the subject has one set.
    pub pinned_post_uri: Option<String>,
    /// Pinned-post CID — content-addressable companion to the URI.
    pub pinned_post_cid: Option<String>,
    /// Whether the AppView's `associated.labeler` flag is set on
    /// this account. Other labelers' policies are themselves a
    /// moderator signal.
    pub is_labeler: bool,
    /// Follow-graph signal: recent followers + follows + mutual
    /// intersection. See the module docs for the moderator
    /// interpretation.
    pub follow_graph: FollowGraph,
    /// Activity-pattern signal: post cadence over the last 30 days,
    /// hour-of-day distribution, weekday distribution, time-since-
    /// last-post. Derived from the same author-feed walk that drives
    /// the media gallery and the reply graph — no additional HTTP
    /// round-trip. The case-view's redesigned follow-graph section
    /// renders this aggregate set instead of the bulky actor lists
    /// the original layout used.
    pub activity_pattern: ActivityPattern,
    /// Reply-graph signal: who the subject replies to, and who
    /// replies to the subject's posts.
    pub reply_graph: ReplyGraph,
    /// Cohort signals: who the subject is socially tight with.
    pub cohort: CohortSignals,
    /// Shared-image cluster signal: blob CIDs the subject has
    /// embedded + which other subjects also embed them.
    pub shared_images: SharedImageSignals,
    /// Source URL for the profile fetch — surfaced so the
    /// moderator can independently verify the upstream data.
    pub source_url: String,
    /// Inline signal-quality flags. `true` means the section was
    /// populated successfully; `false` means the upstream fetch
    /// failed and the section is empty / degraded.
    pub signal_quality: SignalQuality,
}

/// One label entry on a subject's profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContextLabel {
    /// Label value (`spam`, `nsfw`, …).
    pub val: String,
    /// DID of the labeler that issued this label.
    pub src: String,
    /// Human-readable labeler display name resolved via the
    /// AppView's `app.bsky.labeler.getServices`. `None` when the
    /// labeler service record is missing a display name or the
    /// resolution failed — the frontend falls back to rendering
    /// the bare `src` DID.
    #[serde(default)]
    pub src_display_name: Option<String>,
    /// Labeler handle (e.g. `moderation.bsky.app`) when available.
    /// Sourced from the labeler service record's creator profile.
    #[serde(default)]
    pub src_handle: Option<String>,
    /// Target the label was applied to. Either:
    ///   * a bare DID (`did:plc:…`) for account-level labels, OR
    ///   * an AT-URI (`at://did:plc:…/app.bsky.feed.post/…`) for
    ///     record-level labels (post, list, feed).
    ///
    /// The frontend renders post URIs as bsky.app links so the
    /// moderator can click through to the specific labeled post.
    pub uri: String,
    /// Content CID the label is bound to (record-level labels
    /// only). The CID changes when a record is edited; a label
    /// without a matching CID indicates the labeler issued the
    /// label against a since-edited or deleted revision.
    #[serde(default)]
    pub cid: Option<String>,
    /// Negation flag — `true` retracts a prior assertion. The
    /// frontend renders these as "removed at <date>" instead of
    /// "applied at <date>".
    pub neg: bool,
    /// Issuance timestamp from the labeler (`cts` field on the
    /// wire shape). RFC3339; the frontend reformats for display.
    pub cts: Option<String>,
    /// Optional expiry timestamp. Some labelers (notably the
    /// platform moderation labeler) issue time-limited labels; we
    /// surface the expiry so the moderator knows when an
    /// assertion auto-lapses.
    #[serde(default)]
    pub exp: Option<String>,
}

/// One actor entry — used in followers, follows, reply graph, and
/// cohort lists.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct NetworkActor {
    /// Actor DID.
    pub did: String,
    /// Handle, when set and not `handle.invalid`.
    pub handle: Option<String>,
    /// User-edited display name, when set and non-empty.
    pub display_name: Option<String>,
    /// CDN URL of the actor's avatar, when set.
    pub avatar: Option<String>,
}

/// Follow-graph surface: recent followers, recent follows, and
/// the mutual-follow intersection count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowGraph {
    /// Most-recent followers (up to 50). Empty when the AppView
    /// fetch failed.
    pub recent_followers: Vec<NetworkActor>,
    /// Most-recent follows (up to 50). Empty when the AppView
    /// fetch failed.
    pub recent_follows: Vec<NetworkActor>,
    /// Number of DIDs that appear in BOTH `recent_followers` AND
    /// `recent_follows`. The mutual-follow intersection size is
    /// the "embedded in a real social network" signal.
    pub mutual_count: i64,
}

/// Aggregate post-activity signal computed from the subject's
/// author-feed walk.
///
/// Replaces the case-view's previous "recent followers / recent
/// follows" actor lists with derived signals a moderator can read
/// at a glance: how active the account has been, when it posts,
/// and whether the cadence looks human or burst-then-silence.
///
/// All counts are bounded by the author-feed walk window
/// (`AUTHOR_FEED_LIMIT × AUTHOR_FEED_MAX_PAGES` = 300 posts), so
/// the values are "what we observed in the last ~300 posts" rather
/// than lifetime totals. The walk reaches back ~2 weeks for an
/// active account and several years for a dormant one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityPattern {
    /// Number of subject-authored posts (NOT reposts) observed in
    /// the walk window.
    pub total_posts_seen: i64,
    /// Posts whose `indexedAt` falls within the most-recent 7 days.
    pub posts_last_7d: i64,
    /// Posts whose `indexedAt` falls within the most-recent 30 days.
    pub posts_last_30d: i64,
    /// Most-recent post timestamp (RFC 3339), `None` when the walk
    /// returned nothing.
    pub latest_post_at: Option<String>,
    /// 30-day daily-post histogram. Always exactly 30 entries in
    /// oldest → newest order (calendar days, UTC). Days with no
    /// observed activity contribute zero. The first entry is the
    /// calendar day 29 days ago; the last is today.
    pub posts_per_day_30d: Vec<DailyPostCount>,
    /// Hour-of-day distribution (UTC) across the walk window.
    /// Index 0 = `00:00-00:59`, index 23 = `23:00-23:59`.
    /// Useful for spotting bot-like 24x7 cadence vs. human sleep
    /// windows.
    pub posts_per_hour_utc: [i64; 24],
    /// Day-of-week distribution across the walk window. Index 0 =
    /// Monday … index 6 = Sunday (`chrono::Weekday::num_days_from_monday`
    /// convention). Useful for spotting weekend-only / weekday-only
    /// patterns.
    pub posts_per_weekday: [i64; 7],
}

/// One bar of the [`ActivityPattern::posts_per_day_30d`] histogram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyPostCount {
    /// Calendar day in `YYYY-MM-DD` (UTC).
    pub date: String,
    /// Number of subject-authored posts on this day inside the
    /// walked window.
    pub count: i64,
}

/// Reply-graph surface: who the subject replies to + who replies
/// to the subject's posts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyGraph {
    /// Accounts the subject has replied to recently (extracted
    /// from `getAuthorFeed` items whose `reply.parent.author` is
    /// populated). Deduplicated; each appears once.
    pub recent_replies_to: Vec<NetworkActor>,
    /// Accounts that have replied to the subject's recent posts
    /// (parallel `getPostThread` walks across up to 8 of the
    /// subject's most-recent non-reply posts).
    pub recent_repliers: Vec<NetworkActor>,
}

/// Cohort surface: socially-tight clusters derived from the
/// follow + reply graphs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CohortSignals {
    /// Top mutual-follow accounts (intersection of recent
    /// followers and recent follows), capped at 10. The most-
    /// likely real-relationship cluster.
    pub mutual_follow_overlap: Vec<NetworkActor>,
    /// Accounts the subject both follows AND replies to. The
    /// tightest socially-coherent cohort signal.
    pub top_interaction_partners: Vec<NetworkActor>,
}

/// Shared-image cluster surface: blob CIDs the subject embedded
/// + cross-subject matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedImageSignals {
    /// Image blob CIDs found on the subject's most-recent posts
    /// (capped). Each CID represents one image embed.
    pub recent_image_cids: Vec<String>,
    /// Other subjects in Polaris's `subjects` table that have
    /// embedded at least one of `recent_image_cids` in their own
    /// posts. The strongest shared-content signal Polaris can
    /// compute without firehose-side instrumentation.
    pub matched_subjects: Vec<MatchedSubject>,
}

/// One cross-subject match for the shared-image cluster surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedSubject {
    /// The matched subject's `subjects.id` UUID.
    pub subject_id: String,
    /// The matched subject's DID (when available on the row).
    pub did: Option<String>,
    /// Subset of `SharedImageSignals.recent_image_cids` that the
    /// matched subject also embedded.
    pub shared_cids: Vec<String>,
}

/// One image embed extracted from a subject's post. Used as the
/// in-memory shape between [`extract_feed_signals`] and the
/// persistence layer; persisted as one row in
/// `subject_image_blobs` (CID + post URI + alt text + owner DID).
///
/// Named over a bare tuple so the per-field plumbing stays
/// self-documenting at call sites and so future fields (image
/// dimensions, mime type, original blob ref) extend without
/// re-positioning existing arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBlobRecord {
    /// AT-Proto blob CID (content-address).
    pub cid: String,
    /// AT-URI of the post that embedded the blob.
    pub post_uri: String,
    /// DID of the repo that owns the blob — extracted from the
    /// AppView's CDN URL. For the subject's own authored posts
    /// this equals the subject's DID; for embedded quote-post
    /// media (when present) it is the quoted author's DID. The
    /// frontend uses this verbatim as the CDN-URL authority so
    /// the image fetch resolves regardless of provenance.
    pub owner_did: String,
    /// Author-provided alt text from `embed.images[].alt`. `None`
    /// when the field is missing or empty.
    pub alt_text: Option<String>,
    /// AppView-indexed timestamp of the post that embedded this
    /// blob, parsed from `post.indexedAt`. The case-view media
    /// gallery orders by this descending so the carousel walks
    /// newest → oldest. `None` when the field is missing or not
    /// a valid RFC3339 timestamp — those rows fall to the tail
    /// of the carousel via `NULLS LAST` on the read query.
    pub post_indexed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Inline per-section signal-quality flags. Surface a fetch
/// failure to the frontend without poisoning the whole response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four-section flag set is the load-bearing shape — each section is independent \
              and the frontend renders a per-section 'unavailable' state on a `false` flag; \
              collapsing onto an enum loses the per-section discrimination"
)]
pub struct SignalQuality {
    /// `app.bsky.actor.getProfile` fetch succeeded.
    pub profile_loaded: bool,
    /// Both `getFollowers` and `getFollows` succeeded.
    pub follow_graph_loaded: bool,
    /// `getAuthorFeed` succeeded (drives both directions of the
    /// reply graph).
    pub reply_graph_loaded: bool,
    /// Image-blob upsert + cross-subject query succeeded.
    pub shared_images_loaded: bool,
}

// ── Constants ────────────────────────────────────────────────────────

/// Public AppView base URL.
pub(crate) const APPVIEW_BASE_URL: &str = "https://public.api.bsky.app";

// Note: there is no hardcoded labeler list in this file. Issue #181
// removed the previous `WELL_KNOWN_LABELER_DIDS` constant + per-render
// AppView fan-out and replaced them with a single SQL query against
// the local `indexed_labels` table — which is populated by
// `crate::ingest::upstream_labels`'s firehose subscriber per row in
// `upstream_labelers WHERE enabled = TRUE`. The case-view sees every
// label the operator-configured set of labelers has emitted; nothing
// is enumerated in source.

/// Per-fetch timeout. Each independent fetch caps its own
/// `reqwest::Client` at this value; the case-view's overall load
/// time is bounded at roughly this value because the fetches run
/// in parallel.
const FETCH_TIMEOUT_SECS: u64 = 8;

/// Followers/follows page size. The AppView allows up to 100; 50
/// is plenty to compute a meaningful mutual intersection while
/// keeping the response body small.
const FOLLOW_LIMIT: u32 = 50;

/// Author-feed page size. 100 is the AppView maximum and the right
/// choice for the case-view's media gallery: moderators want to
/// examine the full image catalogue a subject has posted, not a
/// 50-item sample. 100 covers a week or two of posting for an
/// active account.
const AUTHOR_FEED_LIMIT: u32 = 100;

/// Maximum number of `getAuthorFeed` pages to walk for the media
/// gallery + reply graph. Each page costs one AppView round-trip,
/// but the pages run in serial because the AppView cursor is the
/// previous page's tail. Three pages × 100 items = up to 300 posts
/// — deep enough to surface every image a subject has shared
/// recently while keeping the case-view load under ~3 seconds even
/// against a slow upstream.
const AUTHOR_FEED_MAX_PAGES: u32 = 3;

/// Number of subject posts to fan out `getPostThread` against for
/// the "who replies to subject" reverse-direction reply graph.
/// 8 keeps the parallel-fetch count bounded.
const REPLY_THREAD_FANOUT: usize = 8;

/// Cap on `mutual_follow_overlap` returned to the frontend.
const COHORT_OVERLAP_CAP: usize = 10;

// ── Handler ──────────────────────────────────────────────────────────

/// Axum handler for `GET /api/cases/{subject_id}/network-context`.
///
/// Resolves the subject's DID from `subjects`, then orchestrates
/// the parallel AppView fetches + shared-image lookup. Returns
/// 404 when the subject does not exist, 400 when the subject row
/// has no `did` populated (post-kind subjects whose authoring DID
/// was not captured), and the typed
/// [`NetworkContextResponse`] otherwise. Upstream-fetch failures
/// do NOT short-circuit the response; the partial-failure
/// semantics live in [`SignalQuality`] inside the body.
#[allow(
    clippy::missing_errors_doc,
    reason = "errors are documented in the function docstring above"
)]
#[tracing::instrument(
    name = "network_context.handler",
    skip(state, _ctx),
    fields(subject_id = %subject_id.0),
)]
pub async fn handler(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
) -> Result<Json<NetworkContextResponse>, ApiError> {
    // Resolve the subject's DID. The row is the authoritative
    // source; we never trust the path id past the SELECT.
    let row = sqlx::query!(r"SELECT did FROM subjects WHERE id = $1", subject_id.0,)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?
        .ok_or(ApiError::NotFound)?;

    let did = row.did.ok_or_else(|| {
        tracing::debug!(
            "network context requested for subject without a DID; surface 400 so the \
             frontend renders the 'no signals available' state",
        );
        ApiError::BadRequest("subject_has_no_did")
    })?;

    // Enqueue a per-(subject, labeler) backfill job for every
    // currently-enabled, non-dormant labeler. The actual queryLabels
    // round-trips run in the background `label_backfill_worker`
    // task; the case-view stays fast and the panel reads
    // `indexed_labels` directly.
    //
    // Idempotent via `ON CONFLICT (subject_did, labeler_did) DO
    // NOTHING` — every render re-enqueues, and rows already in
    // `pending` / `running` / `done` / `permanent_failure` simply
    // absorb the duplicate. No "cache TTL" gymnastics needed; the
    // queue is the source of truth.
    enqueue_backfill_for_subject(&state.pool, &did).await;

    let response = build_network_context(&state.pool, subject_id, &did).await;
    Ok(Json(response))
}

/// Insert one `label_backfill_queue` row for every enabled,
/// non-dormant upstream labeler against this subject.
///
/// The case-view fires this on every render; the unique
/// `(subject_did, labeler_did)` index makes the operation idempotent.
/// New labelers (e.g. ones the discovery worker just inserted) get
/// enqueued the next time a moderator opens the subject — which is
/// fine, because the panel reads `indexed_labels` directly and gets
/// progressively richer as the worker drains the queue.
async fn enqueue_backfill_for_subject(pool: &PgPool, subject_did: &str) {
    // The INSERT ... SELECT shape lets us walk every enabled labeler
    // without bringing the list across the network. Postgres handles
    // the duplicate-key path internally via ON CONFLICT.
    //
    // We exclude dormant labelers here because there is no point
    // enqueuing a queryLabels request against a host the
    // subscribeLabels supervisor has already decided is unreachable;
    // the worker would just time out and the dormancy path would have
    // to re-fire. Dormant rows become eligible again as their
    // `dormant_until` falls in the past, at which point the next
    // case-view render picks them up.
    let result = sqlx::query!(
        r#"
        INSERT INTO label_backfill_queue (subject_did, labeler_did)
        SELECT $1, did
        FROM upstream_labelers
        WHERE enabled = TRUE
          AND (dormant_until IS NULL OR dormant_until <= now())
        ON CONFLICT (subject_did, labeler_did) DO NOTHING
        "#,
        subject_did,
    )
    .execute(pool)
    .await;
    match result {
        Ok(r) => tracing::info!(
            subject_did,
            inserted = r.rows_affected(),
            "label_backfill: enqueued per-labeler rows for subject",
        ),
        Err(err) => tracing::warn!(
            subject_did,
            error = %err,
            "label_backfill: enqueue failed; panel will read current index only",
        ),
    }

    // Touch the `subject_label_backfill` cache row as a UI hint —
    // "we asked for a refresh at this timestamp". The worker is the
    // actual source of truth for queryLabels progress; this row is
    // purely cosmetic. We zero the bookkeeping counters because they
    // are no longer load-bearing under the queue architecture.
    if let Err(err) = sqlx::query!(
        r#"
        INSERT INTO subject_label_backfill (
            subject_did, last_backfilled_at,
            labelers_queried, labelers_succeeded, labels_persisted
        )
        VALUES ($1, now(), 0, 0, 0)
        ON CONFLICT (subject_did) DO UPDATE
        SET last_backfilled_at = EXCLUDED.last_backfilled_at
        "#,
        subject_did,
    )
    .execute(pool)
    .await
    {
        tracing::warn!(
            subject_did,
            error = %err,
            "label_backfill: last-refresh hint write failed; non-fatal",
        );
    }
}

/// Orchestrate the four parallel fetches + the subsequent
/// post-processing (mutual intersection, image blob upsert,
/// shared-image lookup).
///
/// **Partial-failure semantics**: each fetch returns an `Option`
/// (or empty Vec). The handler never fails the whole response
/// because one upstream is down — the panel renders what it has
/// and the `signal_quality` flags surface the failure to the
/// moderator.
#[allow(
    clippy::too_many_lines,
    reason = "five sequential signal sections (profile / follow_graph / reply_graph / cohort / \
              shared_images), each a few-line block of dispatch + extract + map. Splitting into \
              per-section helpers would push the partial-failure flag plumbing across the helper \
              boundary and make the failure semantics harder to follow"
)]
async fn build_network_context(
    pool: &PgPool,
    subject_id: SubjectId,
    did: &str,
) -> NetworkContextResponse {
    let appview =
        std::env::var("POLARIS_APPVIEW_BASE_URL").unwrap_or_else(|_| APPVIEW_BASE_URL.to_owned());

    let client = match build_http_client() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "could not build network-context HTTP client");
            return degraded_response(did, &appview);
        }
    };

    // Four parallel AppView fetches. `tokio::join!` polls each future
    // concurrently on the current task; we don't need
    // tokio::spawn because reqwest's futures are Send and tokio
    // will multiplex them on the runtime's worker pool.
    let profile_url = format!(
        "{appview}/xrpc/app.bsky.actor.getProfile?actor={}",
        encode(did)
    );
    let followers_url = format!(
        "{appview}/xrpc/app.bsky.graph.getFollowers?actor={}&limit={FOLLOW_LIMIT}",
        encode(did)
    );
    let follows_url = format!(
        "{appview}/xrpc/app.bsky.graph.getFollows?actor={}&limit={FOLLOW_LIMIT}",
        encode(did)
    );
    let feed_walk = walk_author_feed(
        &client,
        &appview,
        did,
        AuthorFeedFilter::PostsWithReplies,
        AUTHOR_FEED_MAX_PAGES,
    );
    // Independent label aggregation: for each known labeler, hit
    // its own `com.atproto.label.queryLabels` HTTP endpoint and
    // collect every label that targets the subject's DID. This is
    // the architecture the public `atp-label-indexer` uses (each
    // labeler is treated as a primary source), just executed on
    // demand at case-view render time instead of via a continuous
    // firehose subscription. The AppView's `getProfile.labels`
    // field is NOT consulted because it filters by the
    // `atproto-accept-labelers` header — a list-based mechanism
    // that hides labels from labelers we haven't enumerated.
    let labels_walk = fetch_all_labels_for_subject(pool, did);

    let (profile_res, followers_res, follows_res, feed_pages, aggregated_labels) = tokio::join!(
        get_json(&client, &profile_url),
        get_json(&client, &followers_url),
        get_json(&client, &follows_url),
        feed_walk,
        labels_walk,
    );

    let profile_loaded = profile_res.is_ok();
    let follow_graph_loaded = followers_res.is_ok() && follows_res.is_ok();
    // The walker returns at least an empty Vec; "loaded" means we
    // got at least one successful page back.
    let feed_loaded = !feed_pages.is_empty();

    // --- Profile section ---
    let mut base = match profile_res {
        Ok(body) => map_profile_to_network_context(did, &body, &profile_url),
        Err(err) => {
            tracing::warn!(error = %err, did, "profile fetch failed");
            degraded_response(did, &appview)
        }
    };
    // Override the labels list with the aggregated cross-labeler
    // set. `map_profile_to_network_context` already populates
    // `labels` from `body.labels`, but that field is constrained
    // by AppView filtering and may be empty even when other
    // labelers have applied labels — so we replace it with the
    // direct-from-labeler aggregate. Each [`NetworkContextLabel`]
    // carries the issuing labeler's DID so the panel renders
    // provenance accurately.
    base.labels = aggregated_labels;

    // --- Follow graph section ---
    let recent_followers = followers_res
        .as_ref()
        .ok()
        .map(|b| extract_actor_list(b, "followers"))
        .unwrap_or_default();
    let recent_follows = follows_res
        .as_ref()
        .ok()
        .map(|b| extract_actor_list(b, "follows"))
        .unwrap_or_default();
    let follower_dids: HashSet<&str> = recent_followers.iter().map(|a| a.did.as_str()).collect();
    let follow_dids: HashSet<&str> = recent_follows.iter().map(|a| a.did.as_str()).collect();
    let mutual_dids: Vec<&str> = follower_dids.intersection(&follow_dids).copied().collect();
    let mutual_count = i64::try_from(mutual_dids.len()).unwrap_or(i64::MAX);
    base.follow_graph = FollowGraph {
        recent_followers: recent_followers.clone(),
        recent_follows: recent_follows.clone(),
        mutual_count,
    };

    // --- Activity-pattern section ---
    // Derive cadence + hour-of-day + day-of-week signals from the
    // same author-feed walk that drives the media gallery and the
    // reply graph. No additional HTTP round-trip; we just iterate
    // the in-memory page bodies once more and bucket timestamps.
    base.activity_pattern = compute_activity_pattern(&feed_pages, did, chrono::Utc::now());

    // --- Reply graph section ---
    // Merge the signals from every fetched page. Each page is a
    // standalone `app.bsky.feed.getAuthorFeed` body, so the
    // existing per-page extractor runs unchanged; the merger
    // dedupes reply targets, post URIs, and image CIDs across
    // pages so identical content across the page boundary
    // contributes one entry.
    let (recent_replies_to, subject_post_uris, image_blobs) =
        merge_feed_signals(feed_pages.iter().map(|p| extract_feed_signals(p, did)));

    // Reverse direction: for each of subject's recent non-reply
    // posts, walk getPostThread and collect the top-level reply
    // authors. Bounded fan-out so the case-view load stays fast.
    let reverse_targets: Vec<String> = subject_post_uris
        .into_iter()
        .take(REPLY_THREAD_FANOUT)
        .collect();
    let recent_repliers = if reverse_targets.is_empty() {
        Vec::new()
    } else {
        fetch_replies_to_posts(&client, &appview, &reverse_targets, did).await
    };
    let reply_graph_loaded = feed_loaded;
    base.reply_graph = ReplyGraph {
        recent_replies_to: recent_replies_to.clone(),
        recent_repliers: recent_repliers.clone(),
    };

    // --- Cohort section ---
    let actor_by_did: std::collections::HashMap<&str, &NetworkActor> = recent_followers
        .iter()
        .chain(recent_follows.iter())
        .map(|a| (a.did.as_str(), a))
        .collect();
    let mutual_follow_overlap: Vec<NetworkActor> = mutual_dids
        .iter()
        .take(COHORT_OVERLAP_CAP)
        .filter_map(|did_ref| actor_by_did.get(did_ref).map(|a| (*a).clone()))
        .collect();
    let reply_target_dids: HashSet<&str> =
        recent_replies_to.iter().map(|a| a.did.as_str()).collect();
    let top_interaction_partners: Vec<NetworkActor> = recent_follows
        .iter()
        .filter(|a| reply_target_dids.contains(a.did.as_str()))
        .take(COHORT_OVERLAP_CAP)
        .cloned()
        .collect();
    base.cohort = CohortSignals {
        mutual_follow_overlap,
        top_interaction_partners,
    };

    // --- Shared-image section ---
    let shared_images_loaded = feed_loaded;
    let recent_image_cids: Vec<String> = image_blobs.iter().map(|b| b.cid.clone()).collect();
    let matched_subjects = if image_blobs.is_empty() {
        Vec::new()
    } else {
        match upsert_and_match_blobs(pool, subject_id, &image_blobs).await {
            Ok(matches) => matches,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "subject_image_blobs upsert / lookup failed; rendering panel without \
                     shared-image matches",
                );
                Vec::new()
            }
        }
    };
    base.shared_images = SharedImageSignals {
        recent_image_cids,
        matched_subjects,
    };

    base.signal_quality = SignalQuality {
        profile_loaded,
        follow_graph_loaded,
        reply_graph_loaded,
        shared_images_loaded,
    };

    base
}

// ── HTTP plumbing ────────────────────────────────────────────────────

pub(crate) fn build_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .build()
}

/// One-shot immediate retry budget for transport-layer failures on
/// the AppView fetch path. Mirrors the
/// [`crate::ingest::label_backfill::request_one_page`] constant
/// `PER_PAGE_RETRIES` — the WSL2 host's path to `public.api.bsky.app`
/// is observed to be intermittent (single blackholed TCP attempt
/// followed ~200ms later by a successful one), so one retry absorbs
/// the common case without delaying the degraded-cache fallback.
const PER_REQUEST_RETRIES: usize = 1;

/// Single fetch + JSON decode with a one-shot immediate retry on
/// transport-layer errors.
///
/// Retry policy (mirrors `label_backfill::request_one_page`):
///   * `Ok(resp)` — return as today; status and JSON handling are
///     unchanged below the retry loop.
///   * `Err(reqwest::Error)` on the first attempt — log WARN with
///     the source chain and immediately retry, no backoff sleep.
///   * `Err(reqwest::Error)` on the second attempt — log WARN with
///     `retries_exhausted` and return [`FetchError::Transport`].
///
/// Non-2xx status codes and JSON decode failures are NOT retried:
/// those are terminal upstream signals, not network blackholes. The
/// wrapping handler's degraded-cache path remains the next budget.
async fn get_json(client: &reqwest::Client, url: &str) -> Result<serde_json::Value, FetchError> {
    let mut last_transport_err: Option<String> = None;
    for attempt in 0..=PER_REQUEST_RETRIES {
        match client.get(url).send().await {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    let body = response.text().await.unwrap_or_default();
                    return Err(FetchError::Status(
                        status.as_u16(),
                        body.chars().take(200).collect::<String>(),
                    ));
                }
                return response
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|err| FetchError::Decode(err.to_string()));
            }
            Err(err) => {
                let cause = reqwest_error_chain(&err);
                if attempt < PER_REQUEST_RETRIES {
                    tracing::warn!(
                        url,
                        attempt,
                        error = %err,
                        cause = %cause,
                        "AppView GET transport error; retrying",
                    );
                    last_transport_err = Some(cause);
                    continue;
                }
                tracing::warn!(
                    url,
                    attempts = attempt + 1,
                    error = %err,
                    cause = %cause,
                    "AppView GET transport error; retries_exhausted",
                );
                return Err(FetchError::Transport(cause));
            }
        }
    }
    // Belt-and-braces: the loop body returns on every iteration of
    // `0..=PER_REQUEST_RETRIES`, but the compiler can't see that
    // statically. If we somehow exit the loop, surface the last
    // observed transport error (or a generic marker).
    Err(FetchError::Transport(last_transport_err.unwrap_or_else(
        || "retry loop exited unexpectedly".to_owned(),
    )))
}

/// Walk the `source()` chain of a `reqwest::Error` and return the
/// full cause chain joined by ` → `. Used when the outer Display
/// (`"error sending request"`) hides the actual failure mode
/// (DNS NXDOMAIN, TLS handshake, connect refused, etc.).
///
/// This is duplicated from the canonical implementation at
/// [`crate::ingest::label_backfill::reqwest_error_chain`] to keep
/// this surgical fix contained to a single file. The duplication is
/// intentional: the helper is 12 lines with no shared state, and
/// promoting it to a shared module would require a `pub(crate)`
/// promotion + a re-import everywhere it's called.
fn reqwest_error_chain(err: &reqwest::Error) -> String {
    let mut out = String::new();
    let mut current: Option<&dyn std::error::Error> = std::error::Error::source(err);
    while let Some(cause) = current {
        if !out.is_empty() {
            out.push_str(" → ");
        }
        out.push_str(&cause.to_string());
        current = cause.source();
    }
    if out.is_empty() {
        out.push_str("(no source)");
    }
    out
}

/// Fetch every label targeting `subject_did` from the local
/// `indexed_labels` store.
///
/// This is the bunnynabbit `atp-label-indexer` pattern's query half:
/// the firehose subscriber (`crate::ingest::upstream_labels`) writes
/// every verified label into `indexed_labels` keyed by
/// `(src, uri, val, neg)`; the case-view reads from that table. No
/// AppView round-trip, no hardcoded labeler list, no per-render
/// network fan-out — every label the operator-configured set of
/// labelers has emitted shows up here.
///
/// # The query
///
/// Two cases match a single subject:
///   * account-level labels — `uri = <bare-did>`
///   * record-level labels — `uri LIKE 'at://<did>/%'`
///
/// Both are bound parameters; the SQL builds the prefix with
/// `||` concatenation against `$1`, never via string interpolation.
/// The `indexed_labels_uri_idx` btree index makes the prefix match
/// O(log n) via the left-anchored LIKE.
///
/// # On query failure
///
/// Returns an empty Vec and logs at WARN. The panel renders as
/// "no third-party labels" — degraded but honest — so a transient
/// Postgres blip does not crash the case-view.
///
/// # Display-name enrichment (issue #183)
///
/// `src_display_name` and `src_handle` are populated via a LEFT JOIN
/// against the local `labeler_profiles` cache. Rows without a cached
/// profile come through with `None` for both fields — the frontend
/// falls back to the raw `src` DID for those, and the labeler-
/// discovery worker's lazy refresher fills in the missing entries
/// out-of-band so the next render carries names.
async fn fetch_all_labels_for_subject(
    pool: &PgPool,
    subject_did: &str,
) -> Vec<NetworkContextLabel> {
    // Left-anchored prefix for the LIKE: `at://<did>/`. The trailing
    // slash MUST be present so a DID that prefixes another DID
    // (theoretical but defensive) doesn't accidentally match.
    let glob_prefix = format!("at://{subject_did}/");
    let rows = match sqlx::query!(
        r#"
        SELECT
            il.src,
            il.uri,
            il.cid,
            il.val,
            il.neg,
            il.cts,
            il.exp,
            lp.display_name AS "display_name?",
            lp.handle       AS "handle?"
        FROM indexed_labels il
        LEFT JOIN labeler_profiles lp ON lp.did = il.src
        WHERE il.uri = $1 OR il.uri LIKE $2 || '%'
        ORDER BY il.cts DESC
        "#,
        subject_did,
        glob_prefix,
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(
                subject_did,
                error = %err,
                "failed to read indexed_labels for subject; returning empty panel",
            );
            return Vec::new();
        }
    };

    let out: Vec<NetworkContextLabel> = rows
        .into_iter()
        .map(|r| NetworkContextLabel {
            val: r.val,
            src: r.src,
            // Display-name + handle pulled from labeler_profiles (#183)
            // via the LEFT JOIN above. NULL fields surface as None,
            // and the frontend falls back to the raw DID.
            src_display_name: r.display_name,
            src_handle: r.handle,
            uri: r.uri,
            cid: r.cid,
            neg: r.neg,
            cts: Some(r.cts.to_rfc3339()),
            exp: r.exp.map(|t| t.to_rfc3339()),
        })
        .collect();

    tracing::info!(
        subject_did,
        label_count = out.len(),
        "third-party labels read from local indexed_labels store",
    );
    out
}

#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("status {0}: {1}")]
    Status(u16, String),
    #[error("decode: {0}")]
    Decode(String),
}

/// URL-encode a single query-string value via the `url` crate's
/// form-encoder. Pulled out so the call sites stay readable.
pub(crate) fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

// ── Extractors ───────────────────────────────────────────────────────

/// Convert the public AppView profile body into the wire shape
/// moderators consume. The follow/reply/cohort/shared-image
/// sections are populated separately by the orchestrator; this
/// helper only handles the single-fetch profile fields.
#[must_use]
pub fn map_profile_to_network_context(
    did: &str,
    body: &serde_json::Value,
    source_url: &str,
) -> NetworkContextResponse {
    let str_field = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    let i64_field = |k: &str| body.get(k).and_then(serde_json::Value::as_i64);
    let nonempty = |o: Option<String>| o.filter(|s| !s.is_empty());

    let created_at = str_field("createdAt");
    let account_age_days = created_at.as_deref().and_then(parse_account_age_days);

    let labels = body
        .get("labels")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(extract_network_context_label)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let pinned_post = body.get("pinnedPost");
    let pinned_post_uri = pinned_post
        .and_then(|p| p.get("uri"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let pinned_post_cid = pinned_post
        .and_then(|p| p.get("cid"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);

    let is_labeler = body
        .get("associated")
        .and_then(|a| a.get("labeler"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    NetworkContextResponse {
        did: did.to_owned(),
        handle: nonempty(str_field("handle")).filter(|h| h != "handle.invalid"),
        display_name: nonempty(str_field("displayName")),
        description: nonempty(str_field("description")),
        avatar: str_field("avatar"),
        followers_count: i64_field("followersCount"),
        follows_count: i64_field("followsCount"),
        posts_count: i64_field("postsCount"),
        created_at,
        indexed_at: str_field("indexedAt"),
        account_age_days,
        labels,
        pinned_post_uri,
        pinned_post_cid,
        is_labeler,
        follow_graph: FollowGraph {
            recent_followers: Vec::new(),
            recent_follows: Vec::new(),
            mutual_count: 0,
        },
        activity_pattern: ActivityPattern::default(),
        reply_graph: ReplyGraph {
            recent_replies_to: Vec::new(),
            recent_repliers: Vec::new(),
        },
        cohort: CohortSignals {
            mutual_follow_overlap: Vec::new(),
            top_interaction_partners: Vec::new(),
        },
        shared_images: SharedImageSignals {
            recent_image_cids: Vec::new(),
            matched_subjects: Vec::new(),
        },
        source_url: source_url.to_owned(),
        signal_quality: SignalQuality {
            profile_loaded: true,
            follow_graph_loaded: false,
            reply_graph_loaded: false,
            shared_images_loaded: false,
        },
    }
}

fn parse_account_age_days(rfc3339: &str) -> Option<i64> {
    let created = chrono::DateTime::parse_from_rfc3339(rfc3339).ok()?;
    let now = chrono::Utc::now();
    let delta = now.signed_duration_since(created.with_timezone(&chrono::Utc));
    Some(delta.num_days())
}

fn extract_network_context_label(entry: &serde_json::Value) -> Option<NetworkContextLabel> {
    let val = entry.get("val")?.as_str()?.to_owned();
    let src = entry.get("src")?.as_str()?.to_owned();
    // `uri` is required on the wire shape (`com.atproto.label.defs#label`);
    // a label without one is malformed and we drop it rather than
    // synthesise something rendering-friendly that lies about the
    // target.
    let uri = entry.get("uri")?.as_str()?.to_owned();
    let cid = entry
        .get("cid")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let neg = entry
        .get("neg")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let cts = entry
        .get("cts")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let exp = entry
        .get("exp")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Some(NetworkContextLabel {
        val,
        src,
        // Display fields are populated by a post-fetch enrichment
        // step in `fetch_all_labels_for_subject`; the wire extractor
        // sees only the on-the-wire label payload, not the labeler's
        // profile.
        src_display_name: None,
        src_handle: None,
        uri,
        cid,
        neg,
        cts,
        exp,
    })
}

/// Pull `NetworkActor` entries from a list response. `wrapper_key`
/// is `"followers"` for `getFollowers`, `"follows"` for
/// `getFollows`. Each entry is a `ProfileView` shape with `did`,
/// `handle`, `displayName`, `avatar`.
#[must_use]
pub fn extract_actor_list(body: &serde_json::Value, wrapper_key: &str) -> Vec<NetworkActor> {
    body.get(wrapper_key)
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(actor_from_profile_view)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn actor_from_profile_view(entry: &serde_json::Value) -> Option<NetworkActor> {
    let did = entry.get("did")?.as_str()?.to_owned();
    let nonempty = |k: &str| {
        entry
            .get(k)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let handle = nonempty("handle").filter(|h| h != "handle.invalid");
    Some(NetworkActor {
        did,
        handle,
        display_name: nonempty("displayName"),
        avatar: nonempty("avatar"),
    })
}

/// Walk an `app.bsky.feed.getAuthorFeed` response and pull three
/// signals out:
///
/// 1. Replies (with author): each `feed[].reply.parent.author` is
///    an account the subject has replied to recently.
/// 2. Subject's non-reply post URIs: used as the seed list for the
///    parallel `getPostThread` fan-out that builds
///    `recent_repliers`.
/// 3. Image-embed records: every `feed[].post.embed.images[]`
///    on a SUBJECT-AUTHORED feed item contributes an
///    [`ImageBlobRecord`] (cid + post URI + owner DID + alt text)
///    for the shared-image cluster signal AND the case-view media
///    gallery.
///
/// # Repost filtering
///
/// `subject_did` is the authoritative subject DID. Feed items whose
/// `reason.$type == app.bsky.feed.defs#reasonRepost` are skipped
/// entirely — a repost is the subject amplifying someone else's
/// post, not the subject authoring it, so any media on the
/// underlying post belongs to the original author rather than to
/// the subject's own media gallery. Items whose `post.author.did`
/// does not match `subject_did` are also skipped as a belt-and-
/// suspenders defence against AppView quirks that surface
/// non-subject posts without the `reasonRepost` tag.
///
/// # Owner-DID capture
///
/// The AppView's image URL carries the blob's repo DID as the
/// path segment immediately before the CID. We persist that DID
/// onto the [`ImageBlobRecord`] so the frontend can render the
/// CDN URL with the correct authority regardless of which repo
/// owns the underlying blob (the subject's own DID, in the
/// post-filter set).
///
/// Returns `(recent_replies_to, subject_post_uris, image_blobs)`.
///
/// Cross-page dedup is the caller's job; [`merge_feed_signals`]
/// handles that for the paginated walker.
#[must_use]
pub fn extract_feed_signals(
    body: &serde_json::Value,
    subject_did: &str,
) -> (Vec<NetworkActor>, Vec<String>, Vec<ImageBlobRecord>) {
    let mut replies_to: Vec<NetworkActor> = Vec::new();
    let mut seen_reply_did: HashSet<String> = HashSet::new();
    let mut post_uris: Vec<String> = Vec::new();
    let mut image_blobs: Vec<ImageBlobRecord> = Vec::new();
    let mut seen_cids: HashSet<String> = HashSet::new();

    let Some(feed_arr) = body.get("feed").and_then(serde_json::Value::as_array) else {
        return (replies_to, post_uris, image_blobs);
    };

    for item in feed_arr {
        // Skip reposts: a feed entry whose `reason.$type` is
        // `app.bsky.feed.defs#reasonRepost` is the subject
        // amplifying another account's post, not authoring one.
        // The underlying post's media belongs to the original
        // author and must not appear in the subject's media
        // gallery.
        if is_repost(item) {
            continue;
        }

        let post = item.get("post");
        let post_author_did = post
            .and_then(|p| p.get("author"))
            .and_then(|a| a.get("did"))
            .and_then(serde_json::Value::as_str);
        // Belt-and-suspenders: even if `reason` is absent, the
        // post's author must equal the subject for the item to
        // count as subject-authored content. Drops e.g. cases
        // where the AppView surfaces a non-subject post without
        // a `reason` tag (rare, but defensive).
        let is_subject_authored = post_author_did == Some(subject_did);
        if !is_subject_authored {
            continue;
        }

        let post_uri = post
            .and_then(|p| p.get("uri"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        // Capture `post.indexedAt` — the AppView's ingest
        // timestamp — as the chronological ordering key for the
        // case-view media gallery. Parse failures degrade to
        // `None`, which the read query treats as NULLS LAST.
        let post_indexed_at = post
            .and_then(|p| p.get("indexedAt"))
            .and_then(serde_json::Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        // Reply target — pull the parent author if the item is a
        // reply. Dedup on did so a subject who replies twice to
        // the same account contributes one entry.
        if let Some(reply) = item.get("reply") {
            if let Some(parent_author) = reply.get("parent").and_then(|parent| parent.get("author"))
            {
                if let Some(actor) = actor_from_profile_view(parent_author) {
                    if seen_reply_did.insert(actor.did.clone()) {
                        replies_to.push(actor);
                    }
                }
            }
        } else if let Some(uri) = post_uri.clone() {
            // Non-reply post: candidate for the reverse-direction
            // reply-graph walk.
            post_uris.push(uri);
        }

        // Image embeds — walk `post.embed.images[]` and pull the
        // blob CID + the post URI + the author-provided alt text
        // + the owner DID (from the CDN URL). The embed shape is
        // one of:
        //   * `app.bsky.embed.images#view` (top-level embed)
        //   * `app.bsky.embed.recordWithMedia#view`'s `media` slot
        // We handle both by scanning two paths.
        if let Some(post_obj) = post {
            for embed_path in [
                post_obj.get("embed"),
                post_obj.get("embed").and_then(|e| e.get("media")),
            ] {
                let Some(embed) = embed_path else { continue };
                let Some(images) = embed.get("images").and_then(serde_json::Value::as_array) else {
                    continue;
                };
                for image in images {
                    // The AppView carries the blob's CDN URL on
                    // the image as `fullsize`/`thumb`. We extract
                    // both the owner DID and the CID from the
                    // same URL so the persisted row carries
                    // enough to reconstruct a working URL
                    // regardless of which repo owns the blob.
                    let extracted = image
                        .get("fullsize")
                        .or_else(|| image.get("thumb"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(extract_owner_did_and_cid_from_cdn_url);
                    let Some((owner_did, cid)) = extracted else {
                        continue;
                    };
                    let Some(uri) = post_uri.clone() else {
                        continue;
                    };
                    // `embed.images[].alt` is the author-provided
                    // alternative text. Filter empty strings down
                    // to `None` so the wire shape distinguishes
                    // "author did not provide alt" from "author
                    // provided an empty alt", which simplifies the
                    // frontend's render-when-present branch.
                    let alt_text = image
                        .get("alt")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned);
                    if seen_cids.insert(cid.clone()) {
                        image_blobs.push(ImageBlobRecord {
                            cid,
                            post_uri: uri,
                            owner_did,
                            alt_text,
                            post_indexed_at,
                        });
                    }
                }
            }
        }
    }

    (replies_to, post_uris, image_blobs)
}

/// Compute the [`ActivityPattern`] aggregate from the in-memory
/// author-feed pages.
///
/// Walks every subject-authored, non-repost post entry, extracts its
/// `indexedAt`, and buckets it into the 30-day daily histogram, the
/// 24-hour-of-day distribution, and the 7-day-of-week distribution.
/// `now` is passed in (rather than `Utc::now()` internally) so unit
/// tests can pin a deterministic "today" boundary.
///
/// The result is bounded by the walk window — `AUTHOR_FEED_LIMIT ×
/// AUTHOR_FEED_MAX_PAGES = 300` posts — so the histograms reflect
/// "what we observed", not "lifetime activity".
#[must_use]
pub fn compute_activity_pattern(
    feed_pages: &[serde_json::Value],
    subject_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> ActivityPattern {
    use chrono::{Datelike as _, Duration, Timelike as _};

    // Collect every subject-authored post's indexedAt across all
    // pages. Reposts are skipped (the AppView tags them with
    // `reason.$type == "app.bsky.feed.defs#reasonRepost"`).
    let mut timestamps: Vec<chrono::DateTime<chrono::Utc>> = Vec::new();
    for page in feed_pages {
        let Some(feed) = page.get("feed").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for item in feed {
            if is_repost(item) {
                continue;
            }
            let Some(post) = item.get("post") else {
                continue;
            };
            let author_did = post
                .get("author")
                .and_then(|a| a.get("did"))
                .and_then(serde_json::Value::as_str);
            if author_did != Some(subject_did) {
                continue;
            }
            if let Some(ts) = post
                .get("indexedAt")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc))
            {
                timestamps.push(ts);
            }
        }
    }

    if timestamps.is_empty() {
        return ActivityPattern::default();
    }

    // The 30-day window is anchored on the calendar day containing
    // `now` (UTC). `today_start` is midnight of `now`'s calendar
    // day; bucket 0 is the day 29 days ago, bucket 29 is today.
    let today_start = now.date_naive().and_hms_opt(0, 0, 0).map_or(now, |nd| {
        chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(nd, chrono::Utc)
    });
    let window_start = today_start - Duration::days(29);
    let seven_days_start = now - Duration::days(7);
    let thirty_days_start = now - Duration::days(30);

    let mut posts_last_7d: i64 = 0;
    let mut posts_last_30d: i64 = 0;
    let mut posts_per_hour_utc = [0_i64; 24];
    let mut posts_per_weekday = [0_i64; 7];
    let mut daily_counts = [0_i64; 30];

    for ts in &timestamps {
        if *ts >= seven_days_start {
            posts_last_7d = posts_last_7d.saturating_add(1);
        }
        if *ts >= thirty_days_start {
            posts_last_30d = posts_last_30d.saturating_add(1);
        }
        // Hour-of-day bucket (UTC). `hour()` is `u32` in `0..24`.
        let hour = ts.hour() as usize;
        if hour < 24 {
            posts_per_hour_utc[hour] = posts_per_hour_utc[hour].saturating_add(1);
        }
        // Weekday bucket (Mon=0..Sun=6).
        let weekday = ts.weekday().num_days_from_monday() as usize;
        if weekday < 7 {
            posts_per_weekday[weekday] = posts_per_weekday[weekday].saturating_add(1);
        }
        // Daily-30d bucket. Each entry covers 24h starting at
        // `window_start + N×day`. Posts outside the 30-day window
        // are not bucketed (but still counted toward
        // `total_posts_seen`).
        if *ts >= window_start && *ts < today_start + Duration::days(1) {
            let delta_days = (*ts - window_start).num_days();
            if (0..30).contains(&delta_days) {
                // The (0..30) guard above proves the conversion
                // succeeds; `unwrap_or(0)` is just for clippy's
                // cast-truncation-on-32-bit lint and is never
                // reached on supported targets.
                let idx: usize = usize::try_from(delta_days).unwrap_or(0);
                daily_counts[idx] = daily_counts[idx].saturating_add(1);
            }
        }
    }

    // Materialise the daily histogram with calendar-day labels.
    let mut posts_per_day_30d = Vec::with_capacity(30);
    for (i, count) in daily_counts.iter().enumerate() {
        // `i` is bounded to `0..30` by the iteration over a
        // 30-element array, so the conversion is exact.
        let offset_days = i64::try_from(i).unwrap_or(0);
        let day = window_start + Duration::days(offset_days);
        posts_per_day_30d.push(DailyPostCount {
            date: day.format("%Y-%m-%d").to_string(),
            count: *count,
        });
    }

    let latest_post_at = timestamps
        .iter()
        .max()
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let total_posts_seen = i64::try_from(timestamps.len()).unwrap_or(i64::MAX);

    ActivityPattern {
        total_posts_seen,
        posts_last_7d,
        posts_last_30d,
        latest_post_at,
        posts_per_day_30d,
        posts_per_hour_utc,
        posts_per_weekday,
    }
}

/// True when a feed entry is a repost — i.e., the subject
/// amplifying another account's post rather than authoring one.
///
/// The AppView's `getAuthorFeed` tags reposts with
/// `reason.$type == "app.bsky.feed.defs#reasonRepost"`. Pins
/// (`reasonPin`) are NOT filtered because pinning is the subject
/// elevating their own content — the underlying post still
/// belongs to them.
fn is_repost(item: &serde_json::Value) -> bool {
    item.get("reason")
        .and_then(|r| r.get("$type"))
        .and_then(serde_json::Value::as_str)
        == Some("app.bsky.feed.defs#reasonRepost")
}

/// Merge the per-page outputs of [`extract_feed_signals`] across
/// every fetched author-feed page. Dedup keys mirror the
/// per-page extractor:
///
///   * Reply targets: deduped on DID.
///   * Non-reply post URIs: deduped verbatim.
///   * Image blobs: deduped on CID.
///
/// Preserves insertion order — the first page contributes its
/// signals first, then the second page, etc. — so the case-view
/// renders the moderator's most-recent activity at the top of each
/// list.
fn merge_feed_signals<I>(pages: I) -> (Vec<NetworkActor>, Vec<String>, Vec<ImageBlobRecord>)
where
    I: IntoIterator<Item = (Vec<NetworkActor>, Vec<String>, Vec<ImageBlobRecord>)>,
{
    let mut replies: Vec<NetworkActor> = Vec::new();
    let mut reply_dids_seen: HashSet<String> = HashSet::new();
    let mut uris: Vec<String> = Vec::new();
    let mut post_uris_seen: HashSet<String> = HashSet::new();
    let mut blobs: Vec<ImageBlobRecord> = Vec::new();
    let mut blob_cids_seen: HashSet<String> = HashSet::new();

    for (page_replies, page_uris, page_blobs) in pages {
        for actor in page_replies {
            if reply_dids_seen.insert(actor.did.clone()) {
                replies.push(actor);
            }
        }
        for uri in page_uris {
            if post_uris_seen.insert(uri.clone()) {
                uris.push(uri);
            }
        }
        for blob in page_blobs {
            if blob_cids_seen.insert(blob.cid.clone()) {
                blobs.push(blob);
            }
        }
    }
    (replies, uris, blobs)
}

/// Walk `app.bsky.feed.getAuthorFeed` across up to
/// [`AUTHOR_FEED_MAX_PAGES`] pages and return every successfully-
/// fetched page's body. Stops early on transport failure, empty
/// `cursor`, or empty `feed` (the AppView returns no cursor when
/// the subject has no more posts).
///
/// The pages run in serial because each request needs the previous
/// response's `cursor`; the per-page latency is bounded by the
/// shared `FETCH_TIMEOUT_SECS` so the whole walk is bounded by
/// `AUTHOR_FEED_MAX_PAGES × FETCH_TIMEOUT_SECS`. We deliberately
/// do NOT enforce a global walk deadline — the per-page deadline
/// already produces backpressure on a slow upstream, and adding
/// a global one would risk truncating the second page mid-decode
/// (and losing dozens of in-flight image embeds) for the sake of
/// a marginal latency win the moderator does not perceive.
pub(crate) async fn walk_author_feed(
    client: &reqwest::Client,
    appview: &str,
    did: &str,
    filter: AuthorFeedFilter,
    max_pages: u32,
) -> Vec<serde_json::Value> {
    let mut pages: Vec<serde_json::Value> = Vec::new();
    let mut cursor: Option<String> = None;
    let filter_token = filter.as_str();

    for _ in 0..max_pages {
        let mut url = format!(
            "{appview}/xrpc/app.bsky.feed.getAuthorFeed\
             ?actor={}&limit={AUTHOR_FEED_LIMIT}&filter={filter_token}",
            encode(did)
        );
        if let Some(c) = cursor.as_deref() {
            url.push_str("&cursor=");
            url.push_str(&encode(c));
        }
        let body = match get_json(client, &url).await {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(error = %err, did, "author-feed page fetch failed");
                break;
            }
        };
        // Pull the next cursor BEFORE moving the body into the
        // pages vector — otherwise the borrow lifetime conflicts
        // with the `pages.push(body)` move.
        let next_cursor = body
            .get("cursor")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let feed_len = body
            .get("feed")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        pages.push(body);
        // Stop if the AppView told us there are no more pages, or
        // if the page came back empty (defensive — pre-empts the
        // edge case where a non-empty cursor returns an empty
        // feed, which would otherwise burn the page budget on
        // no-op fetches).
        match next_cursor {
            Some(c) if feed_len > 0 => cursor = Some(c),
            _ => break,
        }
    }
    pages
}

/// Wire-token enumeration of the `filter` parameter on
/// `app.bsky.feed.getAuthorFeed`. The values match the AppView's
/// own vocabulary — passing an invented value would silently
/// degrade the request to the default filter.
///
/// The two call sites that exist today need different filters:
///
/// * `network_context` wants `posts_with_replies` so the reply-
///   graph extractor sees the subject's reply parents.
/// * `media` wants `posts_with_media` so every page yields only
///   media-bearing posts — maximises image yield per request and
///   makes the deep walk affordable.
#[derive(Debug, Clone, Copy)]
pub(crate) enum AuthorFeedFilter {
    /// Surfaces both standalone posts and replies; the reply-graph
    /// extractor relies on the replies being present.
    PostsWithReplies,
    /// Filters to posts that embed any media (image, video, GIF).
    /// The media-gallery walker uses this so each page yields
    /// maximum-density image embeds.
    PostsWithMedia,
}

impl AuthorFeedFilter {
    /// The wire token sent on the `filter=` query string.
    fn as_str(self) -> &'static str {
        match self {
            Self::PostsWithReplies => "posts_with_replies",
            Self::PostsWithMedia => "posts_with_media",
        }
    }
}

/// Extract `(owner_did, blob_cid)` from a Bluesky CDN URL.
///
/// The CDN URL shape is:
/// `https://cdn.bsky.app/img/feed_thumbnail/plain/<owner-did>/<blob-cid>@<format>`
///
/// Concretely:
/// `https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:abc123/bafyreiabc@jpeg`
///
/// We pluck the owner DID (the segment immediately before the
/// final `/`) and the CID (the segment between the final `/` and
/// the `@`). Returns `None` on any shape mismatch so a malformed
/// URL doesn't trip the gallery.
///
/// The DID is validated by `did:` prefix only — both `did:plc:…`
/// and `did:web:…` are accepted (and any future ATProto DID
/// method that adopts the `did:` scheme).
fn extract_owner_did_and_cid_from_cdn_url(url: &str) -> Option<(String, String)> {
    let last_slash = url.rfind('/')?;
    let owner_end = last_slash;
    let owner_start = url[..owner_end].rfind('/')? + 1;
    let owner_did = &url[owner_start..owner_end];
    let tail = &url[last_slash + 1..];
    let at_pos = tail.find('@').unwrap_or(tail.len());
    let cid = &tail[..at_pos];
    if !owner_did.starts_with("did:") {
        return None;
    }
    if !cid.starts_with("bafy") && !cid.starts_with("bafk") {
        return None;
    }
    Some((owner_did.to_owned(), cid.to_owned()))
}

// ── Reverse-direction reply-graph fan-out ────────────────────────────

/// For each of the subject's recent non-reply posts, fetch
/// `getPostThread` and collect the unique top-level reply
/// authors. The fan-out is parallel via `futures::future::join_all`
/// so the wall-clock cost is one round-trip, not N round-trips.
async fn fetch_replies_to_posts(
    client: &reqwest::Client,
    appview: &str,
    post_uris: &[String],
    subject_did: &str,
) -> Vec<NetworkActor> {
    // Each future owns its own `url` `String` so the borrow does
    // not escape the closure. `async move` captures `url` by value,
    // and `client` is `&reqwest::Client` (Clone is cheap — it's an
    // internal Arc — but the borrow is fine because every future
    // outlives the loop).
    let fetches = post_uris.iter().map(|uri| {
        let url = format!(
            "{appview}/xrpc/app.bsky.feed.getPostThread\
             ?uri={}&depth=1&parentHeight=0",
            encode(uri)
        );
        async move { get_json(client, &url).await }
    });
    let results = futures::future::join_all(fetches).await;

    let mut repliers: Vec<NetworkActor> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(subject_did.to_owned());

    for result in results {
        let Ok(body) = result else { continue };
        let Some(thread) = body.get("thread") else {
            continue;
        };
        let Some(reply_list) = thread.get("replies").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for reply in reply_list {
            // `reply.post.author` is a ProfileViewBasic.
            let Some(author) = reply.get("post").and_then(|p| p.get("author")) else {
                continue;
            };
            let Some(actor) = actor_from_profile_view(author) else {
                continue;
            };
            // Subject replying to its own thread isn't a "replier"
            // signal; skip the subject's own DID. Dedup the rest.
            if seen.insert(actor.did.clone()) {
                repliers.push(actor);
            }
        }
    }
    repliers
}

// ── Shared-image upsert + match ──────────────────────────────────────

/// Persist the `(subject, cid, post_uri)` triples we just extracted
/// from the feed AND query `subject_image_blobs` for OTHER subjects
/// that share any of the same CIDs. Returns the matched subjects.
async fn upsert_and_match_blobs(
    pool: &PgPool,
    subject_id: SubjectId,
    image_blobs: &[ImageBlobRecord],
) -> Result<Vec<MatchedSubject>, sqlx::Error> {
    if image_blobs.is_empty() {
        return Ok(Vec::new());
    }

    // Upsert: a separate INSERT per row keeps the SQL simple and
    // each fires `ON CONFLICT (subject_id, blob_cid, post_uri) DO
    // UPDATE SET alt_text = EXCLUDED.alt_text` so a re-walk that
    // sees newly-added alt text on an already-known blob row
    // updates the column (authors do edit alt text after the
    // fact, and a missing-then-present transition is itself a
    // moderator signal). The row count is bounded by the image-
    // embed count of the subject's recent posts (typically dozens
    // across the three-page walk), so the per-row INSERT overhead
    // is immaterial against the upstream HTTP latency we just paid.
    for blob in image_blobs {
        sqlx::query!(
            r"INSERT INTO subject_image_blobs
                  (subject_id, blob_cid, post_uri, alt_text, owner_did,
                   post_indexed_at, walked_at)
              VALUES ($1, $2, $3, $4, $5, $6, now())
              ON CONFLICT (subject_id, blob_cid, post_uri)
              DO UPDATE SET
                  alt_text        = EXCLUDED.alt_text,
                  owner_did       = EXCLUDED.owner_did,
                  post_indexed_at = EXCLUDED.post_indexed_at,
                  walked_at       = now()",
            subject_id.0,
            blob.cid,
            blob.post_uri,
            blob.alt_text.as_deref(),
            blob.owner_did,
            blob.post_indexed_at,
        )
        .execute(pool)
        .await?;
    }

    // Lookup: for each CID, find OTHER subjects that have embedded
    // it. The aggregation groups by matched subject so the
    // frontend renders one row per match with the set of shared
    // CIDs.
    let cids: Vec<String> = image_blobs.iter().map(|b| b.cid.clone()).collect();
    let rows = sqlx::query!(
        r"SELECT
            sib.subject_id      AS subject_id,
            s.did               AS did,
            array_agg(DISTINCT sib.blob_cid) AS shared_cids
          FROM subject_image_blobs sib
          JOIN subjects s ON s.id = sib.subject_id
          WHERE sib.blob_cid = ANY($1)
            AND sib.subject_id <> $2
          GROUP BY sib.subject_id, s.did
          ORDER BY sib.subject_id",
        &cids,
        subject_id.0,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| MatchedSubject {
            subject_id: r.subject_id.to_string(),
            did: r.did,
            shared_cids: r.shared_cids.unwrap_or_default(),
        })
        .collect())
}

/// Default response for the "everything failed" path. Carries the
/// DID we know about + empty signal sections so the frontend can
/// render the panel even when no upstream data is reachable.
fn degraded_response(did: &str, appview: &str) -> NetworkContextResponse {
    NetworkContextResponse {
        did: did.to_owned(),
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
        follow_graph: FollowGraph {
            recent_followers: Vec::new(),
            recent_follows: Vec::new(),
            mutual_count: 0,
        },
        activity_pattern: ActivityPattern::default(),
        reply_graph: ReplyGraph {
            recent_replies_to: Vec::new(),
            recent_repliers: Vec::new(),
        },
        cohort: CohortSignals {
            mutual_follow_overlap: Vec::new(),
            top_interaction_partners: Vec::new(),
        },
        shared_images: SharedImageSignals {
            recent_image_cids: Vec::new(),
            matched_subjects: Vec::new(),
        },
        source_url: format!("{appview}/xrpc/app.bsky.actor.getProfile"),
        signal_quality: SignalQuality {
            profile_loaded: false,
            follow_graph_loaded: false,
            reply_graph_loaded: false,
            shared_images_loaded: false,
        },
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    fn fixture_profile() -> serde_json::Value {
        serde_json::json!({
            "did": "did:plc:abc123",
            "handle": "alice.bsky.social",
            "displayName": "Alice",
            "description": "Test bio",
            "avatar": "https://cdn.bsky.app/img/avatar/.../alice.jpg",
            "followersCount": 42,
            "followsCount": 100,
            "postsCount": 13,
            "createdAt": "2024-01-15T12:00:00.000Z",
            "indexedAt": "2026-05-01T00:00:00.000Z",
            "labels": [
                {"val": "spam", "src": "did:plc:labeler-1", "uri": "did:plc:abc123", "neg": false, "cts": "2026-01-01T00:00:00Z"},
                {"val": "verified", "src": "did:plc:labeler-2", "uri": "did:plc:abc123", "neg": false, "cts": "2026-02-01T00:00:00Z"},
            ],
            "pinnedPost": {
                "uri": "at://did:plc:abc123/app.bsky.feed.post/xyz",
                "cid": "bafyabc123"
            },
            "associated": {"labeler": false, "chat": {"allowIncoming": "all"}}
        })
    }

    #[test]
    fn map_profile_extracts_canonical_fields() {
        let nc = map_profile_to_network_context(
            "did:plc:abc123",
            &fixture_profile(),
            "https://public.api.bsky.app/xrpc/...",
        );
        assert_eq!(nc.did, "did:plc:abc123");
        assert_eq!(nc.handle.as_deref(), Some("alice.bsky.social"));
        assert_eq!(nc.display_name.as_deref(), Some("Alice"));
        assert_eq!(nc.followers_count, Some(42));
        assert_eq!(nc.follows_count, Some(100));
        assert_eq!(nc.posts_count, Some(13));
        assert_eq!(nc.labels.len(), 2);
        assert!(!nc.is_labeler);
    }

    #[test]
    fn map_profile_treats_handle_invalid_as_none() {
        let body = serde_json::json!({"did": "did:plc:abc", "handle": "handle.invalid"});
        let nc = map_profile_to_network_context("did:plc:abc", &body, "url");
        assert!(nc.handle.is_none());
    }

    #[test]
    fn map_profile_skips_label_entries_missing_val_or_src() {
        // The wire shape `com.atproto.label.defs#label` requires
        // `val`, `src`, and `uri`. Entries missing any of those
        // must be dropped — they're malformed and we'd rather
        // surface "labels.len() == 2" than render a half-built
        // row with synthesised defaults.
        let body = serde_json::json!({
            "did": "did:plc:abc",
            "labels": [
                {"val": "good", "src": "did:plc:l1", "uri": "did:plc:abc"},
                {"src": "did:plc:l2", "uri": "did:plc:abc"},
                {"val": "missing-src", "uri": "did:plc:abc"},
                {"val": "missing-uri", "src": "did:plc:l4"},
                {"val": "also-good", "src": "did:plc:l3", "uri": "did:plc:abc"},
            ]
        });
        let nc = map_profile_to_network_context("did:plc:abc", &body, "url");
        assert_eq!(nc.labels.len(), 2);
    }

    #[test]
    fn extract_actor_list_pulls_followers() {
        let body = serde_json::json!({
            "followers": [
                {"did": "did:plc:a", "handle": "a.bsky.social", "displayName": "A"},
                {"did": "did:plc:b", "handle": "b.bsky.social"},
                {"did": "did:plc:c", "handle": "handle.invalid"},
            ]
        });
        let list = extract_actor_list(&body, "followers");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].did, "did:plc:a");
        assert_eq!(list[0].display_name.as_deref(), Some("A"));
        assert!(list[1].display_name.is_none());
        assert!(list[2].handle.is_none()); // handle.invalid → None
    }

    #[test]
    fn extract_actor_list_handles_missing_wrapper() {
        let body = serde_json::json!({"unrelated": "field"});
        let list = extract_actor_list(&body, "followers");
        assert!(list.is_empty());
    }

    #[test]
    fn extract_feed_signals_pulls_replies_and_images() {
        let body = serde_json::json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:s/app.bsky.feed.post/p1",
                        "author": {"did": "did:plc:s"},
                        "embed": {
                            "images": [
                                {
                                    "fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafyABC@jpeg",
                                    "alt": "an annotated screenshot"
                                },
                                {"thumb": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafkDEF@jpeg"},
                            ]
                        }
                    }
                },
                {
                    "post": {
                        "uri": "at://did:plc:s/app.bsky.feed.post/p2",
                        "author": {"did": "did:plc:s"}
                    },
                    "reply": {
                        "parent": {
                            "author": {"did": "did:plc:target", "handle": "target.bsky.social"}
                        }
                    }
                },
            ]
        });
        let (replies_to, post_uris, blobs) = extract_feed_signals(&body, "did:plc:s");
        assert_eq!(replies_to.len(), 1);
        assert_eq!(replies_to[0].did, "did:plc:target");
        assert_eq!(post_uris.len(), 1);
        assert_eq!(post_uris[0], "at://did:plc:s/app.bsky.feed.post/p1");
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].cid, "bafyABC");
        assert_eq!(blobs[0].owner_did, "did:plc:s");
        assert_eq!(
            blobs[0].alt_text.as_deref(),
            Some("an annotated screenshot")
        );
        assert_eq!(blobs[1].cid, "bafkDEF");
        assert_eq!(blobs[1].owner_did, "did:plc:s");
        // The second image had no `alt` field; the extractor must
        // surface `None` rather than `Some("")`.
        assert!(blobs[1].alt_text.is_none());
    }

    #[test]
    fn extract_feed_signals_captures_post_indexed_at() {
        // The AppView's `post.indexedAt` carries an RFC3339
        // timestamp; the extractor must parse it onto the
        // `ImageBlobRecord` so the read query can order the
        // gallery in strict reverse-chronological order.
        let body = serde_json::json!({
            "feed": [{
                "post": {
                    "uri": "at://did:plc:s/app.bsky.feed.post/p1",
                    "author": {"did": "did:plc:s"},
                    "indexedAt": "2026-05-15T12:34:56Z",
                    "embed": {
                        "images": [{
                            "fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafyABC@jpeg"
                        }]
                    }
                }
            }]
        });
        let (_, _, blobs) = extract_feed_signals(&body, "did:plc:s");
        assert_eq!(blobs.len(), 1);
        let parsed = blobs[0].post_indexed_at.expect("indexedAt parsed");
        assert_eq!(parsed.to_rfc3339(), "2026-05-15T12:34:56+00:00");
    }

    #[test]
    fn extract_feed_signals_indexed_at_missing_or_malformed_becomes_none() {
        // Three pathological shapes: no indexedAt key, empty
        // string, and a non-RFC3339 value. Each must surface as
        // `None` rather than producing a parse panic or a bogus
        // timestamp.
        let body = serde_json::json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:s/app.bsky.feed.post/p1",
                        "author": {"did": "did:plc:s"},
                        "embed": {"images": [{"fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafy1@jpeg"}]}
                    }
                },
                {
                    "post": {
                        "uri": "at://did:plc:s/app.bsky.feed.post/p2",
                        "author": {"did": "did:plc:s"},
                        "indexedAt": "",
                        "embed": {"images": [{"fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafy2@jpeg"}]}
                    }
                },
                {
                    "post": {
                        "uri": "at://did:plc:s/app.bsky.feed.post/p3",
                        "author": {"did": "did:plc:s"},
                        "indexedAt": "not a timestamp",
                        "embed": {"images": [{"fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafy3@jpeg"}]}
                    }
                }
            ]
        });
        let (_, _, blobs) = extract_feed_signals(&body, "did:plc:s");
        assert_eq!(blobs.len(), 3);
        for b in &blobs {
            assert!(b.post_indexed_at.is_none(), "expected None for {}", b.cid);
        }
    }

    #[test]
    fn extract_feed_signals_skips_reposts() {
        // A `reasonRepost` feed entry must contribute zero rows
        // to the subject's media gallery — the underlying post
        // belongs to another author.
        let body = serde_json::json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/p1",
                        "author": {"did": "did:plc:other"},
                        "embed": {
                            "images": [
                                {"fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:other/bafyOTHER@jpeg"}
                            ]
                        }
                    },
                    "reason": {
                        "$type": "app.bsky.feed.defs#reasonRepost",
                        "by": {"did": "did:plc:s"}
                    }
                },
                {
                    "post": {
                        "uri": "at://did:plc:s/app.bsky.feed.post/p2",
                        "author": {"did": "did:plc:s"},
                        "embed": {
                            "images": [
                                {"fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafyOWN@jpeg"}
                            ]
                        }
                    }
                }
            ]
        });
        let (_, _, blobs) = extract_feed_signals(&body, "did:plc:s");
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].cid, "bafyOWN");
        assert_eq!(blobs[0].owner_did, "did:plc:s");
    }

    #[test]
    fn extract_feed_signals_skips_non_subject_authored() {
        // Belt-and-suspenders: a post whose `author.did` does not
        // match the subject is dropped even when no `reasonRepost`
        // tag is present. The AppView occasionally surfaces these
        // for thread-context reasons; they are not subject media.
        let body = serde_json::json!({
            "feed": [{
                "post": {
                    "uri": "at://did:plc:other/app.bsky.feed.post/p1",
                    "author": {"did": "did:plc:other"},
                    "embed": {
                        "images": [{
                            "fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:other/bafyABC@jpeg"
                        }]
                    }
                }
            }]
        });
        let (_, _, blobs) = extract_feed_signals(&body, "did:plc:s");
        assert!(blobs.is_empty());
    }

    #[test]
    fn extract_feed_signals_treats_blank_alt_as_none() {
        // Authors that hit "save" on the alt-text input without
        // typing anything end up with an empty string on the
        // wire. The case-view should treat that as "no alt text
        // provided" — semantically identical to a missing field —
        // so the carousel renders the same empty-state hint for
        // both.
        let body = serde_json::json!({
            "feed": [{
                "post": {
                    "uri": "at://did:plc:s/app.bsky.feed.post/p3",
                    "author": {"did": "did:plc:s"},
                    "embed": {
                        "images": [
                            {
                                "fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafyEMP@jpeg",
                                "alt": "   "
                            },
                            {
                                "fullsize": "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafyXYZ@jpeg",
                                "alt": ""
                            }
                        ]
                    }
                }
            }]
        });
        let (_, _, blobs) = extract_feed_signals(&body, "did:plc:s");
        assert_eq!(blobs.len(), 2);
        assert!(blobs[0].alt_text.is_none());
        assert!(blobs[1].alt_text.is_none());
    }

    #[test]
    fn merge_feed_signals_dedupes_across_pages() {
        // Two pages with overlapping image CID + reply target;
        // the merger must keep the first occurrence and skip the
        // dup.
        let page_a = (
            vec![NetworkActor {
                did: "did:plc:rep".to_owned(),
                handle: Some("a.test".to_owned()),
                display_name: None,
                avatar: None,
            }],
            vec!["at://did:plc:s/app.bsky.feed.post/p1".to_owned()],
            vec![ImageBlobRecord {
                cid: "bafyABC".to_owned(),
                post_uri: "at://did:plc:s/app.bsky.feed.post/p1".to_owned(),
                owner_did: "did:plc:s".to_owned(),
                alt_text: Some("first".to_owned()),
                post_indexed_at: None,
            }],
        );
        let page_b = (
            vec![NetworkActor {
                did: "did:plc:rep".to_owned(), // dup
                handle: Some("a.test".to_owned()),
                display_name: None,
                avatar: None,
            }],
            vec![
                "at://did:plc:s/app.bsky.feed.post/p1".to_owned(), // dup
                "at://did:plc:s/app.bsky.feed.post/p2".to_owned(),
            ],
            vec![
                ImageBlobRecord {
                    cid: "bafyABC".to_owned(), // dup
                    post_uri: "at://did:plc:s/app.bsky.feed.post/p2".to_owned(),
                    owner_did: "did:plc:s".to_owned(),
                    alt_text: None,
                    post_indexed_at: None,
                },
                ImageBlobRecord {
                    cid: "bafyDEF".to_owned(),
                    post_uri: "at://did:plc:s/app.bsky.feed.post/p2".to_owned(),
                    owner_did: "did:plc:s".to_owned(),
                    alt_text: Some("second image".to_owned()),
                    post_indexed_at: None,
                },
            ],
        );
        let (replies, uris, blobs) = merge_feed_signals([page_a, page_b]);
        assert_eq!(replies.len(), 1);
        assert_eq!(uris.len(), 2);
        // First-occurrence wins: bafyABC carries the alt from page A.
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].cid, "bafyABC");
        assert_eq!(blobs[0].alt_text.as_deref(), Some("first"));
        assert_eq!(blobs[1].cid, "bafyDEF");
    }

    #[test]
    fn extract_feed_signals_dedups_reply_targets() {
        // Each item is a subject-authored reply (post.author.did
        // matches the subject); the parent's author DID is the
        // dedup key for `recent_replies_to`.
        let body = serde_json::json!({
            "feed": [
                {
                    "post": {"uri": "at://did:plc:s/app.bsky.feed.post/p1", "author": {"did": "did:plc:s"}},
                    "reply": {"parent": {"author": {"did": "did:plc:x", "handle": "x.test"}}}
                },
                {
                    "post": {"uri": "at://did:plc:s/app.bsky.feed.post/p2", "author": {"did": "did:plc:s"}},
                    "reply": {"parent": {"author": {"did": "did:plc:x", "handle": "x.test"}}}
                },
                {
                    "post": {"uri": "at://did:plc:s/app.bsky.feed.post/p3", "author": {"did": "did:plc:s"}},
                    "reply": {"parent": {"author": {"did": "did:plc:y", "handle": "y.test"}}}
                },
            ]
        });
        let (replies_to, _, _) = extract_feed_signals(&body, "did:plc:s");
        assert_eq!(replies_to.len(), 2);
    }

    #[test]
    fn extract_owner_did_and_cid_from_cdn_url_pulls_both() {
        assert_eq!(
            extract_owner_did_and_cid_from_cdn_url(
                "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:s/bafyABC@jpeg"
            ),
            Some(("did:plc:s".to_owned(), "bafyABC".to_owned()))
        );
        assert_eq!(
            extract_owner_did_and_cid_from_cdn_url(
                "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:abc123/bafkLMN@png"
            ),
            Some(("did:plc:abc123".to_owned(), "bafkLMN".to_owned()))
        );
    }

    #[test]
    fn extract_owner_did_and_cid_from_cdn_url_accepts_did_web() {
        // `did:web:` is a valid ATProto DID method; the CDN
        // honours it identically to `did:plc:`.
        assert_eq!(
            extract_owner_did_and_cid_from_cdn_url(
                "https://cdn.bsky.app/img/feed_thumbnail/plain/did:web:example.com/bafyZ@jpeg"
            ),
            Some(("did:web:example.com".to_owned(), "bafyZ".to_owned()))
        );
    }

    #[test]
    fn extract_owner_did_and_cid_from_cdn_url_rejects_non_cid_segment() {
        // The CID segment must look like an AT-Proto blob CID
        // (multibase v1 starts with `bafy` or `bafk`). Anything
        // else is treated as a non-image URL — defensive against
        // shape drift.
        assert!(
            extract_owner_did_and_cid_from_cdn_url("https://example.com/profile.jpg").is_none()
        );
        assert!(extract_owner_did_and_cid_from_cdn_url("https://example.com/").is_none());
        assert!(extract_owner_did_and_cid_from_cdn_url("not-a-url").is_none());
    }

    #[test]
    fn extract_owner_did_and_cid_from_cdn_url_rejects_non_did_owner() {
        // If the segment preceding the CID is not a DID, the URL
        // came from somewhere unexpected — refuse rather than
        // store a malformed owner.
        assert!(
            extract_owner_did_and_cid_from_cdn_url("https://example.com/cdn/random/bafyABC@jpeg")
                .is_none()
        );
    }

    // Note: tests asserting on `WELL_KNOWN_LABELER_DIDS` were
    // removed in #181 when the hardcoded list was deleted. The
    // labeler set is now operator-managed via `upstream_labelers`
    // and indexed locally; there is no compile-time constant to
    // assert against. Coverage moved to:
    //   * `ingest::upstream_labels::tests` — local-store write path
    //   * `polaris-backend/tests/upstream_labelers.rs` — end-to-end
    //     verify-and-persist via `handle_frame_with_seq`
    //   * #182 / #183 follow-ups — automatic labeler discovery and
    //     display-name enrichment.

    #[test]
    fn url_encode_basic_did() {
        assert_eq!(encode("did:plc:abc"), "did%3Aplc%3Aabc");
    }

    #[test]
    fn url_encode_safe_characters() {
        // ASCII letters and digits pass through verbatim.
        assert_eq!(encode("alice"), "alice");
        assert_eq!(encode("abc123"), "abc123");
    }

    #[test]
    fn parse_account_age_days_recent_account() {
        let recent = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        let days = parse_account_age_days(&recent).expect("parse should succeed");
        assert!((2..=4).contains(&days), "expected ~3 days, got {days}");
    }

    #[test]
    fn parse_account_age_days_garbage() {
        assert!(parse_account_age_days("not a date").is_none());
        assert!(parse_account_age_days("").is_none());
    }

    /// `compute_activity_pattern` with no pages returns a default
    /// (all-zeros) result. Avoids divide-by-zero in downstream
    /// histogram normalisation.
    #[test]
    fn compute_activity_pattern_empty_pages_returns_default() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-17T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let pat = compute_activity_pattern(&[], "did:plc:x", now);
        assert_eq!(pat.total_posts_seen, 0);
        assert_eq!(pat.posts_last_7d, 0);
        assert_eq!(pat.posts_last_30d, 0);
        assert!(pat.posts_per_day_30d.is_empty());
        assert!(pat.latest_post_at.is_none());
    }

    /// Buckets a small feed correctly: posts spread across last
    /// 7/30 days land in the right per-day / hour / weekday cells.
    #[test]
    fn compute_activity_pattern_buckets_timestamps() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-17T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // Three posts: 1h ago, 5d ago at 08:00 UTC (Tue), 60d ago.
        let one_hour_ago =
            (now - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let five_days_ago = chrono::DateTime::parse_from_rfc3339("2026-05-12T08:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let five_days_ago_s = five_days_ago.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let sixty_days_ago =
            (now - chrono::Duration::days(60)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let page = serde_json::json!({
            "feed": [
                {"post": {"author": {"did": "did:plc:s"}, "indexedAt": one_hour_ago}},
                {"post": {"author": {"did": "did:plc:s"}, "indexedAt": five_days_ago_s}},
                {"post": {"author": {"did": "did:plc:s"}, "indexedAt": sixty_days_ago}},
                // Repost — must be excluded.
                {"reason": {"$type": "app.bsky.feed.defs#reasonRepost"},
                 "post": {"author": {"did": "did:plc:s"}, "indexedAt": one_hour_ago}},
                // Other author's post — must be excluded.
                {"post": {"author": {"did": "did:plc:other"}, "indexedAt": one_hour_ago}},
            ]
        });
        let pat = compute_activity_pattern(&[page], "did:plc:s", now);
        assert_eq!(
            pat.total_posts_seen, 3,
            "3 subject-authored, non-repost posts"
        );
        assert_eq!(pat.posts_last_7d, 2, "1h-ago + 5d-ago");
        assert_eq!(pat.posts_last_30d, 2, "60d-ago falls outside the window");
        assert_eq!(
            pat.posts_per_day_30d.len(),
            30,
            "30-day histogram always 30 entries"
        );
        // Hour buckets — 11:00 UTC (now-1h) and 08:00 UTC.
        assert!(pat.posts_per_hour_utc[11] >= 1);
        assert!(pat.posts_per_hour_utc[8] >= 1);
        // Weekday — 2026-05-12 is a Tuesday → index 1.
        assert!(pat.posts_per_weekday[1] >= 1);
        // Latest must be the most recent.
        assert!(pat.latest_post_at.is_some());
    }

    /// Daily histogram is anchored on UTC calendar days: a post
    /// "today" lands in the last bucket, a post "29 days ago" lands
    /// in the first.
    #[test]
    fn compute_activity_pattern_daily_histogram_anchors_correctly() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-17T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let today = "2026-05-17T01:00:00Z";
        let twenty_nine_days_ago = "2026-04-18T01:00:00Z";
        let page = serde_json::json!({
            "feed": [
                {"post": {"author": {"did": "did:plc:s"}, "indexedAt": today}},
                {"post": {"author": {"did": "did:plc:s"}, "indexedAt": twenty_nine_days_ago}},
            ]
        });
        let pat = compute_activity_pattern(&[page], "did:plc:s", now);
        assert_eq!(pat.posts_per_day_30d.len(), 30);
        // First entry covers 2026-04-18, last covers 2026-05-17.
        assert_eq!(pat.posts_per_day_30d[0].date, "2026-04-18");
        assert_eq!(pat.posts_per_day_30d[0].count, 1);
        assert_eq!(pat.posts_per_day_30d[29].date, "2026-05-17");
        assert_eq!(pat.posts_per_day_30d[29].count, 1);
    }

    #[test]
    fn map_profile_is_labeler_true_when_associated_set() {
        let body = serde_json::json!({"did": "did:plc:l", "associated": {"labeler": true}});
        let nc = map_profile_to_network_context("did:plc:l", &body, "url");
        assert!(nc.is_labeler);
    }

    /// `get_json` must absorb a single transport-layer failure by
    /// immediately retrying once. We stack two wiremock matchers at
    /// the same `(method, path)` pair:
    ///
    ///   * a high-priority matcher with `up_to_n_times(1)` that
    ///     uses `respond_with_err` to close the connection abruptly
    ///     — this is the production "blackhole" shape simulated as
    ///     a transport-level error rather than a non-2xx status,
    ///   * a fallback matcher returning `200 + {"ok": true}` that
    ///     handles every subsequent call.
    ///
    /// On the first attempt `get_json` observes a `reqwest::Error`
    /// (connection-closed); the production retry path catches it,
    /// logs at WARN, and reissues the request — that second call
    /// hits the fallback matcher and decodes successfully.
    ///
    /// If the retry path is ever removed (or the budget is reduced
    /// to zero), this test fails with `FetchError::Transport`.
    /// Standalone error type used by the retry test below to
    /// drive wiremock's `respond_with_err` path. Lifted to module
    /// scope so the test body satisfies `items_after_statements`.
    #[derive(Debug, thiserror::Error)]
    #[error("simulated blackhole")]
    struct SimulatedBlackhole;

    #[tokio::test]
    async fn get_json_retries_once_on_transport_error_then_succeeds() {
        let server = wiremock::MockServer::start().await;

        // First attempt: simulate a transport-level failure. The
        // `respond_with_err` path drops the TCP connection without
        // a response, which `reqwest` surfaces as an
        // `Err(reqwest::Error)` — exactly the production blackhole
        // shape this retry was added to absorb.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/probe"))
            .respond_with_err(|_: &wiremock::Request| SimulatedBlackhole)
            .up_to_n_times(1)
            .with_priority(1) // higher priority than the fallback
            .mount(&server)
            .await;

        // Retry attempt + every subsequent call: success.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/probe"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})),
            )
            .with_priority(5)
            .mount(&server)
            .await;

        let client = build_http_client().expect("test client builds");
        let url = format!("{}/probe", server.uri());
        let body = get_json(&client, &url)
            .await
            .expect("retry must absorb the simulated blackhole");
        assert_eq!(body, serde_json::json!({"ok": true}));
    }

    /// Regression guard: the retry budget is exactly 1.
    /// Increasing it without auditing the wrapping handler's
    /// degraded-cache budget would inflate worst-case panel
    /// latency past the `FETCH_TIMEOUT_SECS × (1 + retries)`
    /// ceiling the operator expects.
    #[test]
    fn per_request_retries_is_exactly_one() {
        assert_eq!(PER_REQUEST_RETRIES, 1);
    }

    #[test]
    fn degraded_response_carries_did_and_zero_signals() {
        let r = degraded_response("did:plc:x", "https://public.api.bsky.app");
        assert_eq!(r.did, "did:plc:x");
        assert!(!r.signal_quality.profile_loaded);
        assert!(!r.signal_quality.follow_graph_loaded);
        assert_eq!(r.follow_graph.mutual_count, 0);
        assert!(r.follow_graph.recent_followers.is_empty());
        assert!(r.reply_graph.recent_replies_to.is_empty());
        assert!(r.shared_images.recent_image_cids.is_empty());
    }
}
