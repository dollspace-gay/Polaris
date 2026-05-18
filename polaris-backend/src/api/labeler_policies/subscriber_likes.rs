//! Subscriber-likes telemetry — wires the
//! `app.bsky.labeler.getServices` upstream into a process-local TTL
//! cache so the `LabelerPoliciesResponse.subscriber_likes` field
//! surfaces real counts.
//!
//! # Why a cache
//!
//! The labeler-policies endpoint is hit by the moderator's
//! `ActionComposer` on every render of the subscriber-effect
//! preview. Fan-out is small (one moderator per workstation) but
//! a per-keystroke AppView round-trip would (a) burn the AppView's
//! rate budget for the operator's account and (b) make the preview
//! feel laggy. Subscriber count is a slowly-changing signal — a
//! five-minute TTL is plenty.
//!
//! The cache is process-global: a single Polaris instance has a
//! single operator DID, so the cached entry is shared across every
//! request the process serves. The cache value is `Option<u32>` so
//! a successful "no subscriber count available" lookup (e.g., the
//! AppView returned a view without `likeCount`) caches a `None`
//! and avoids repeated upstream calls.
//!
//! # Failure mode
//!
//! Cache misses that fail upstream do NOT poison the cache —
//! returning `Err` lets the handler fall back to `subscriber_likes
//! = None` for that single request, and the next request re-tries
//! the upstream. The cache only stores successful lookups (positive
//! AND `None` results) keyed by the time of fetch.

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::api::network_context::{APPVIEW_BASE_URL, build_http_client, encode};
use sqlx::PgPool;

/// Cache TTL. Subscriber count is a slowly-changing signal; the
/// composer preview tolerates five-minute staleness easily.
const CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Process-global TTL cache for the operator's subscriber-likes
/// count. `Mutex<...>` rather than `RwLock` because the cache
/// holds two cheap values and contention is negligible at our
/// fan-out.
static LIKES_CACHE: LazyLock<Mutex<Option<CacheEntry>>> = LazyLock::new(|| Mutex::new(None));

#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    value: Option<u32>,
    fetched_at: Instant,
}

/// Fetch the operator's labeler-likes count, consulting the process
/// cache and refreshing on miss.
///
/// `pool` is used to resolve the operator's labeler DID from
/// `polaris_setup_state.labeler_record_uri`. Returns `Ok(None)`
/// when:
///   * The setup wizard has not yet published a labeler record
///     (no `labeler_record_uri` to parse), OR
///   * The AppView returned no `likeCount` for the labeler view, OR
///   * The upstream fetch failed (the failure is logged and the
///     caller falls back to the AT-Proto-reference-defaults
///     caveat).
///
/// Returns `Err(_)` only on database failures unrelated to the
/// fetch itself — the policies handler treats those as 500s.
pub(crate) async fn fetch_subscriber_likes(pool: &PgPool) -> Result<Option<u32>, sqlx::Error> {
    // Cache short-circuit. We hold the lock only long enough to
    // read the fresh-or-stale check; the actual upstream fetch
    // happens unlocked so concurrent requests don't serialise.
    if let Some(entry) = read_fresh_entry() {
        return Ok(entry.value);
    }

    // Resolve the operator's labeler DID from the persisted
    // labeler-record AT-URI. Shape: `at://<did>/app.bsky.labeler.service/self`.
    let row = sqlx::query!(r"SELECT labeler_record_uri FROM polaris_setup_state WHERE id = TRUE",)
        .fetch_one(pool)
        .await?;

    let Some(labeler_did) = row
        .labeler_record_uri
        .as_deref()
        .and_then(parse_labeler_did_from_record_uri)
    else {
        // Setup wizard has not yet published a record — there is
        // no upstream to consult. Cache a None for the TTL window
        // so subsequent renders don't keep hitting the database.
        store_entry(None);
        return Ok(None);
    };

    let value = upstream_lookup(&labeler_did).await;
    store_entry(value);
    Ok(value)
}

/// Read the cached entry if it is still inside the TTL window.
/// Returning `None` indicates "cache miss; caller must refresh".
fn read_fresh_entry() -> Option<CacheEntry> {
    let guard = LIKES_CACHE.lock().ok()?;
    let entry = (*guard)?;
    if entry.fetched_at.elapsed() < CACHE_TTL {
        Some(entry)
    } else {
        None
    }
}

/// Store a fresh entry in the cache with `now()` as the fetch time.
fn store_entry(value: Option<u32>) {
    if let Ok(mut guard) = LIKES_CACHE.lock() {
        *guard = Some(CacheEntry {
            value,
            fetched_at: Instant::now(),
        });
    }
}

/// Hit the AppView's `app.bsky.labeler.getServices` and extract the
/// `likeCount` for our labeler view.
///
/// Returns `Some(count)` on success, `None` on any of:
///   * HTTP client construction failure (only at process startup
///     under exotic rustls misconfig),
///   * Non-2xx response from the AppView,
///   * JSON decode failure,
///   * Missing `views[0].likeCount` field,
///   * `likeCount` outside `u32` range.
///
/// Each failure case logs at WARN with the cause so an operator
/// debugging a permanently-stuck subscriber-count can grep the
/// logs.
async fn upstream_lookup(labeler_did: &str) -> Option<u32> {
    let client = match build_http_client() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "subscriber-likes: HTTP client build failed");
            return None;
        }
    };
    let appview =
        std::env::var("POLARIS_APPVIEW_BASE_URL").unwrap_or_else(|_| APPVIEW_BASE_URL.to_owned());
    let url = format!(
        "{appview}/xrpc/app.bsky.labeler.getServices?dids={}&detailed=true",
        encode(labeler_did),
    );
    let body: serde_json::Value = match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                tracing::warn!(
                    %status,
                    %labeler_did,
                    "subscriber-likes: getServices non-2xx",
                );
                return None;
            }
            match resp.json::<serde_json::Value>().await {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(error = %err, "subscriber-likes: JSON decode failed");
                    return None;
                }
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "subscriber-likes: transport failure");
            return None;
        }
    };

    extract_like_count(&body)
}

/// Pluck `views[0].likeCount` from the AppView response.
///
/// The `getServices` response shape is:
/// ```text
/// {
///   "views": [
///     { "$type": "...#labelerViewDetailed", "likeCount": 1234, ... }
///   ]
/// }
/// ```
///
/// A response with an empty `views` array is treated as `None`
/// (the labeler exists but the AppView has no detailed view to
/// report, which happens during initial-publish propagation). A
/// `likeCount` that exceeds `u32::MAX` is also treated as `None`
/// rather than truncated — the cap is generous (4 billion) and
/// any actual overflow is more likely an upstream bug than a real
/// count.
fn extract_like_count(body: &serde_json::Value) -> Option<u32> {
    let raw = body
        .get("views")?
        .as_array()?
        .first()?
        .get("likeCount")?
        .as_u64()?;
    u32::try_from(raw).ok()
}

/// Parse the labeler DID out of an AT-URI of the form
/// `at://<did>/app.bsky.labeler.service/self`.
///
/// Returns `None` on any shape mismatch (the wizard validates the
/// URI shape before persisting, so a malformed value in the
/// column is a defensive case rather than an expected one).
fn parse_labeler_did_from_record_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("at://")?;
    let did = rest.split('/').next()?;
    if did.starts_with("did:") {
        Some(did.to_owned())
    } else {
        None
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
    fn parse_labeler_did_extracts_did_plc() {
        let did = parse_labeler_did_from_record_uri(
            "at://did:plc:xukcocedc7p2hem733mu4vqh/app.bsky.labeler.service/self",
        );
        assert_eq!(did.as_deref(), Some("did:plc:xukcocedc7p2hem733mu4vqh"));
    }

    #[test]
    fn parse_labeler_did_accepts_did_web() {
        let did = parse_labeler_did_from_record_uri(
            "at://did:web:example.com/app.bsky.labeler.service/self",
        );
        assert_eq!(did.as_deref(), Some("did:web:example.com"));
    }

    #[test]
    fn parse_labeler_did_rejects_non_at_scheme() {
        assert!(parse_labeler_did_from_record_uri("https://example.com/x").is_none());
        assert!(parse_labeler_did_from_record_uri("").is_none());
    }

    #[test]
    fn parse_labeler_did_rejects_non_did_authority() {
        assert!(
            parse_labeler_did_from_record_uri("at://example.com/app.bsky.labeler.service/self")
                .is_none()
        );
    }

    #[test]
    fn extract_like_count_pulls_first_view() {
        let body = serde_json::json!({
            "views": [
                {
                    "$type": "app.bsky.labeler.defs#labelerViewDetailed",
                    "likeCount": 12_345_u64,
                }
            ]
        });
        assert_eq!(extract_like_count(&body), Some(12_345));
    }

    #[test]
    fn extract_like_count_handles_zero() {
        // A freshly-published labeler has zero likes; the cache
        // must distinguish `Some(0)` ("fetched, count is zero")
        // from `None` ("could not fetch / no view available").
        let body = serde_json::json!({
            "views": [{ "likeCount": 0 }]
        });
        assert_eq!(extract_like_count(&body), Some(0));
    }

    #[test]
    fn extract_like_count_missing_views_array() {
        assert_eq!(extract_like_count(&serde_json::json!({})), None);
    }

    #[test]
    fn extract_like_count_empty_views_array() {
        assert_eq!(extract_like_count(&serde_json::json!({"views": []})), None);
    }

    #[test]
    fn extract_like_count_missing_field_on_view() {
        let body = serde_json::json!({
            "views": [{ "$type": "...#labelerViewDetailed" }]
        });
        assert_eq!(extract_like_count(&body), None);
    }

    #[test]
    fn extract_like_count_overflow_treated_as_none() {
        // A `likeCount` larger than u32::MAX is more likely an
        // upstream bug than a real count; refuse to truncate.
        let body = serde_json::json!({
            "views": [{ "likeCount": u64::from(u32::MAX) + 1 }]
        });
        assert_eq!(extract_like_count(&body), None);
    }
}
