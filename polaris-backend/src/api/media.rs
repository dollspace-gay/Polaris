//! `GET /api/cases/{subject_id}/media` — case-view media gallery.
//!
//! Triggers an on-demand deep walk of the subject's
//! `app.bsky.feed.getAuthorFeed` (filter=`posts_with_media`,
//! paginated until the cursor empties or
//! [`MEDIA_FEED_MAX_PAGES`] is reached), persists every newly-seen
//! `(blob_cid, post_uri, alt_text, owner_did)` quadruple into
//! `subject_image_blobs`, reaps cached rows that the current walk
//! did not observe, and returns the deduped list as a
//! [`MediaGalleryResponse`].
//!
//! # Why a dedicated endpoint
//!
//! The case-view DTO's `media_blobs` field reads from
//! `subject_image_blobs` synchronously — fast, but only reflects
//! whatever a *previous* call cached. The dedicated endpoint
//! refreshes that cache on demand, the same way `<NetworkPanel>`
//! refreshes its surface on mount via `/network-context`. Case
//! view paints instantly; the gallery resolves a beat later with
//! the complete, post-filter set.
//!
//! # Repost filtering
//!
//! `getAuthorFeed` returns BOTH the subject's authored posts AND
//! the subject's reposts of others' posts. The reposts surface as
//! feed items tagged `reason.$type ==
//! "app.bsky.feed.defs#reasonRepost"` with the original author's
//! `post` payload — the underlying media belongs to that original
//! author, not the subject. The extractor in
//! [`crate::api::network_context::extract_feed_signals`] drops
//! those items entirely (see also the belt-and-suspenders
//! `post.author.did != subject_did` filter), so only
//! subject-authored media reaches the gallery.
//!
//! # Stale-row reap
//!
//! Each upsert sets `walked_at = now()`. After the walk completes
//! the handler issues `DELETE FROM subject_image_blobs WHERE
//! subject_id = $1 AND walked_at < $walk_started_at` to drop:
//!
//!   * Rows from pre-fix walks that were never owner-DID-aware
//!     and may include reposts the filter now excludes.
//!   * Rows for posts the subject has since deleted (the AppView
//!     will no longer surface them, so the new walk won't observe
//!     them, so they fall below the cutoff and get reaped).
//!
//! Concurrent walks each carry their own `walk_started_at`, so a
//! peer walk's fresh inserts (`walked_at = now()`) are strictly
//! above this walk's cutoff and never get caught by the DELETE.
//!
//! # Performance
//!
//! Each page hits the AppView with the per-fetch timeout shared
//! across all upstream calls (see
//! [`crate::api::network_context::FETCH_TIMEOUT_SECS`]). The
//! [`MEDIA_FEED_MAX_PAGES`] cap is the safety bound; in practice
//! most subjects exhaust their feed within a fraction of that
//! budget because `filter=posts_with_media` already skips the
//! text-only posts. With `AUTHOR_FEED_LIMIT = 100` and an active
//! account, 1-3 seconds is typical.
//!
//! # Authorization
//!
//! Routed under the authed subtree — any moderator role can fetch
//! the gallery for any subject they can access through the rest
//! of the case-view surface. The auth gate exists so Polaris does
//! not become an unauthenticated AppView proxy; the data itself
//! is public ATProto repo content.

use axum::Json;
use axum::extract::{Extension, Path, State};
use chrono::{DateTime, Utc};
use polaris_types::SubjectId;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::dto::SubjectMediaBlob;
use crate::api::error::ApiError;
use crate::api::network_context::{
    APPVIEW_BASE_URL, AuthorFeedFilter, ImageBlobRecord, build_http_client, extract_feed_signals,
    walk_author_feed,
};
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;

/// Maximum pages of `getAuthorFeed` the media-gallery walker is
/// allowed to consume in a single refresh.
///
/// Trades wall-clock against completeness. The walker stops early
/// the moment the AppView returns no cursor (the natural "end of
/// feed" signal), so this cap only bites for extremely prolific
/// accounts. 30 × 100 = 3000 media posts is enough to cover years
/// of posting for typical accounts.
const MEDIA_FEED_MAX_PAGES: u32 = 30;

/// Wire shape for `GET /api/cases/{subject_id}/media`.
///
/// Carries the full deduped media list (one entry per unique blob
/// CID, ordered newest-first) plus an `upstream_ok` flag the
/// frontend uses to render a "could not refresh" hint when the
/// walker failed but the cache still had rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaGalleryResponse {
    /// One entry per distinct blob CID. Ordered most-recent first.
    pub blobs: Vec<SubjectMediaBlob>,
    /// `true` when the AppView walk returned at least one page;
    /// `false` when every page fetch failed (the `blobs` list, if
    /// any, comes from the table's prior cache and may be stale).
    pub upstream_ok: bool,
}

/// Axum handler for `GET /api/cases/{subject_id}/media`.
///
/// Resolves the subject's DID, runs the deep AppView walk, persists
/// every new blob+alt+owner triple, reaps stale rows, and returns
/// the deduped list.
///
/// # Errors
///
/// - `404` when the subject id does not match a row.
/// - `400` (`subject_has_no_did`) when the subject has no DID
///   populated. List- / feed-kind subjects fall into this bucket;
///   they have no authoring DID and therefore no media to walk.
/// - `500` only on database failures unrelated to the walk —
///   AppView failures degrade to the cached set with
///   `upstream_ok = false`, not a 5xx.
#[tracing::instrument(
    name = "media.handler",
    skip(state, _ctx),
    fields(subject_id = %subject_id.0),
)]
pub async fn handler(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
) -> Result<Json<MediaGalleryResponse>, ApiError> {
    let row = sqlx::query!(r"SELECT did FROM subjects WHERE id = $1", subject_id.0,)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?
        .ok_or(ApiError::NotFound)?;

    let did = row.did.ok_or_else(|| {
        tracing::debug!(
            "media gallery requested for subject without a DID; surface 400 so the \
             frontend renders the 'no images available' state",
        );
        ApiError::BadRequest("subject_has_no_did")
    })?;

    let upstream_ok = refresh_subject_media(&state.pool, subject_id, &did).await?;
    let blobs = read_media_blobs(&state.pool, subject_id).await?;
    Ok(Json(MediaGalleryResponse { blobs, upstream_ok }))
}

/// Walk the subject's author feed (media filter) and upsert every
/// image embed found into `subject_image_blobs`, then reap any
/// cached rows the current walk did not observe.
///
/// Returns `true` when at least one page came back from the
/// AppView (the cache is fresh as of this call); `false` when
/// every page fetch failed (the cache holds whatever a prior
/// successful walk persisted, possibly nothing).
async fn refresh_subject_media(
    pool: &PgPool,
    subject_id: SubjectId,
    did: &str,
) -> Result<bool, ApiError> {
    // Capture the cutoff BEFORE the walk starts so concurrent
    // walks each reap only rows older than their own start
    // (their fresh inserts carry a later `walked_at`).
    let walk_started_at: DateTime<Utc> = Utc::now();

    let appview =
        std::env::var("POLARIS_APPVIEW_BASE_URL").unwrap_or_else(|_| APPVIEW_BASE_URL.to_owned());

    let client = match build_http_client() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "could not build media-walker HTTP client");
            return Ok(false);
        }
    };

    let pages = walk_author_feed(
        &client,
        &appview,
        did,
        AuthorFeedFilter::PostsWithMedia,
        MEDIA_FEED_MAX_PAGES,
    )
    .await;
    if pages.is_empty() {
        return Ok(false);
    }

    // Aggregate every image record across every fetched page,
    // deduplicating on CID. `extract_feed_signals` filters reposts
    // and non-subject-authored items before we ever see the row.
    let mut seen_cids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut all_blobs: Vec<ImageBlobRecord> = Vec::new();
    for page in &pages {
        let (_replies, _post_uris, page_blobs) = extract_feed_signals(page, did);
        for blob in page_blobs {
            if seen_cids.insert(blob.cid.clone()) {
                all_blobs.push(blob);
            }
        }
    }

    tracing::info!(
        did,
        pages = pages.len(),
        unique_images = all_blobs.len(),
        "media-walker observed subject-authored images",
    );

    // Per-row upsert with conflict-aware alt-text / owner-DID
    // update + walked_at bump. The same shape as
    // `network_context::upsert_and_match_blobs` (kept duplicated
    // because each call site sits inside an instrument span with
    // its own labelled context — folding onto a shared helper
    // would obscure the tracing fields).
    for blob in &all_blobs {
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
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;
    }

    // Reap rows the current walk did not observe — see the
    // module docs for the reap-cutoff rationale. The DELETE is
    // a no-op when there are no stale rows.
    let reaped = sqlx::query!(
        r"DELETE FROM subject_image_blobs
          WHERE subject_id = $1 AND walked_at < $2",
        subject_id.0,
        walk_started_at,
    )
    .execute(pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?
    .rows_affected();
    if reaped > 0 {
        tracing::info!(did, reaped, "reaped stale subject_image_blobs rows",);
    }

    Ok(true)
}

/// Read the deduped media list for a subject from
/// `subject_image_blobs`, newest-first.
///
/// Mirrors the SELECT in `api::cases::build_media_blobs` so the
/// case-view DTO field and the dedicated endpoint return the same
/// rows in the same order.
async fn read_media_blobs(
    pool: &PgPool,
    subject_id: SubjectId,
) -> Result<Vec<SubjectMediaBlob>, ApiError> {
    // Dedup-on-CID inside the subquery keeps the most-recent
    // post per unique blob (DISTINCT ON winner = first row of the
    // ORDER BY group, so we order the inner by
    // `post_indexed_at DESC NULLS LAST, first_seen_at DESC` —
    // newest post wins, and rows with no parsed timestamp fall
    // back to the observation time). The outer ORDER BY then
    // produces strict reverse-chronological order, with
    // legacy NULL-timestamped rows pushed to the tail of the
    // carousel.
    let rows = sqlx::query!(
        r#"
        SELECT blob_cid, post_uri, alt_text, owner_did, post_indexed_at, first_seen_at
        FROM (
            SELECT DISTINCT ON (blob_cid)
                blob_cid,
                post_uri,
                alt_text,
                owner_did,
                post_indexed_at,
                first_seen_at
            FROM subject_image_blobs
            WHERE subject_id = $1
            ORDER BY blob_cid, post_indexed_at DESC NULLS LAST, first_seen_at DESC
        ) AS distinct_blobs
        ORDER BY post_indexed_at DESC NULLS LAST, first_seen_at DESC
        "#,
        subject_id.0,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(rows
        .into_iter()
        .map(|r| SubjectMediaBlob {
            blob_cid: r.blob_cid,
            post_uri: r.post_uri,
            alt_text: r.alt_text,
            owner_did: r.owner_did,
            post_indexed_at: r.post_indexed_at,
            first_seen_at: r.first_seen_at,
        })
        .collect())
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
    fn media_gallery_response_round_trips_through_serde() {
        let posted_at = chrono::Utc::now();
        let body = MediaGalleryResponse {
            blobs: vec![SubjectMediaBlob {
                blob_cid: "bafyABC".to_owned(),
                post_uri: "at://did:plc:x/app.bsky.feed.post/3kfoo".to_owned(),
                alt_text: Some("annotated screenshot".to_owned()),
                owner_did: Some("did:plc:x".to_owned()),
                post_indexed_at: Some(posted_at),
                first_seen_at: chrono::Utc::now(),
            }],
            upstream_ok: true,
        };
        let json = serde_json::to_string(&body).expect("serialize");
        let back: MediaGalleryResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.blobs.len(), 1);
        assert_eq!(back.blobs[0].blob_cid, "bafyABC");
        assert_eq!(back.blobs[0].owner_did.as_deref(), Some("did:plc:x"));
        assert_eq!(
            back.blobs[0].alt_text.as_deref(),
            Some("annotated screenshot")
        );
        assert_eq!(back.blobs[0].post_indexed_at, Some(posted_at));
        assert!(back.upstream_ok);
    }

    #[test]
    fn media_gallery_response_serialises_empty_blobs() {
        let body = MediaGalleryResponse {
            blobs: Vec::new(),
            upstream_ok: false,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert!(json["blobs"].is_array());
        assert_eq!(json["blobs"].as_array().expect("array shape").len(), 0);
        assert_eq!(json["upstream_ok"], false);
    }
}
