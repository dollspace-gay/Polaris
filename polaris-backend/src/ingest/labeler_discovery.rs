//! PLC-directory labeler discovery (issue #182).
//!
//! Polaris is an Ozone replacement; the case-view's "third-party labels"
//! panel needs to surface every label any labeler in the AT-Proto network
//! has issued against a subject. To make that comprehensive without
//! hardcoding a labeler list, this module walks the public PLC directory
//! at <https://plc.directory/export>, finds every DID whose current
//! state declares an `atproto_labeler` service, and inserts the DID into
//! `upstream_labelers`. The existing per-upstream firehose consumer
//! (`crate::ingest::upstream_labels::UpstreamLabelerConsumer`) then
//! subscribes to each labeler's `subscribeLabels` stream and writes
//! every verified label into the local `indexed_labels` store — which
//! the case-view reads.
//!
//! # Cold-start cost: 2-3 hours on a fresh deploy
//!
//! The PLC log contains ~10M+ DID operations going back to November
//! 2022; labeler service records are rare events scattered through
//! that history. The crawler walks 1000 ops per page with a 250ms
//! inter-page backoff (PLC is community infrastructure; we do not
//! hammer it). The realistic time budget is:
//!
//! | Phase                                              | Wall-clock |
//! |----------------------------------------------------|-----------|
//! | Walk 2022-11 → 2024-01 (pre-labeler era)           | ~30 min   |
//! | Walk 2024-01 → 2025-01 (early labeler ecosystem)   | ~45 min   |
//! | Walk 2025-01 → present                             | ~60 min   |
//! | **Bootstrap total**                                | **~2-3 hours** |
//!
//! During the bootstrap, the case-view's third-party-labels panel
//! shows zero labels for any subject. This is expected behaviour —
//! see `docs/ops/runbook.md` §1a "Labeler discovery cold-start" and
//! `docs/ops/quick-start.md` §7 for the operator-facing documentation
//! of this trade-off. Once `last_after` has caught up to the live
//! edge, subsequent delta passes (every [`INTER_CRAWL_INTERVAL`])
//! complete in seconds.
//!
//! Operators who need a faster cold-start can pre-seed
//! `upstream_labelers` via direct SQL before starting Polaris; the
//! supervisor honours operator-added rows identically to discovery-
//! added rows.
//!
//! # Why PLC export, not the bsky firehose
//!
//! Two discovery channels are available:
//!
//! 1. **PLC export** (this module) — paginated chronological dump of
//!    every DID operation ever recorded on the PLC directory. Gives
//!    historical coverage: every labeler that has ever existed is
//!    discoverable, even ones that haven't emitted a record on the
//!    bsky firehose in years.
//! 2. **bsky firehose** — observe `app.bsky.labeler.service` record
//!    commits as they arrive. Catches *new* labelers in real time but
//!    cannot discover labelers that existed before the worker first
//!    connected.
//!
//! For an Ozone-replacement workload that wants comprehensive
//! retrospective coverage, PLC-export-walk is the only complete
//! source. (1) is implemented here; (2) is filed as a follow-up
//! when the firehose worker lands.
//!
//! # Crawl strategy
//!
//! - The PLC export endpoint accepts `?after=<isoTimestamp>&count=1000`
//!   and returns up to `count` JSON-Lines records of operations whose
//!   `createdAt` strictly exceeds `after`.
//! - Each record's `operation` is either a legacy `type: "create"` or a
//!   modern `type: "plc_operation"`. Only `plc_operation` ops carry the
//!   `services` map; we filter on `services.atproto_labeler` presence.
//! - The crawler persists `last_after` in `plc_export_cursor` after
//!   every page, so a restart picks up exactly where the previous run
//!   left off. The initial run from `last_after = ''` covers ~10M
//!   ops; subsequent delta runs only fetch new ops since the cursor.
//! - When `last_after == ''` we issue the URL without `?after=` so the
//!   PLC directory interprets it as "start at the beginning of the
//!   log". The endpoint sorts ascending by `createdAt` so we advance
//!   the cursor monotonically.
//!
//! # Discovery → spawn
//!
//! Inserts into `upstream_labelers` fire a `tokio::sync::Notify` so the
//! supervisor task ([`crate::ingest::labeler_supervisor`]) wakes up
//! and spawns a fresh [`UpstreamLabelerConsumer`] for each newly-added
//! row — without restarting the process.
//!
//! # Forbidden patterns
//!
//! - No `unwrap()`/`expect()` outside `#[cfg(test)]`.
//! - No string-built SQL; every DB write is `sqlx::query!`.
//! - No `unsafe`.
//! - No tight-loop retry — fetch failures honour exponential backoff
//!   via the standard `tokio::time::sleep` cadence.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Default upstream URL for the PLC export endpoint. Operators
/// running their own PLC mirror can override via the
/// `POLARIS_PLC_DIRECTORY_URL` env var. The path is appended by
/// the crawler so this value should be the base URL only.
const DEFAULT_PLC_BASE_URL: &str = "https://plc.directory";

/// Maximum records per `?count=N` page. The PLC directory caps at
/// 1000; smaller values trade more round-trips for less risk of
/// timing out on a slow connection.
const PAGE_SIZE: i32 = 1000;

/// Per-page HTTP timeout. The PLC service is generally fast (sub-
/// second), but a generous ceiling absorbs transient network blips
/// without crashing the crawler.
const FETCH_TIMEOUT_SECS: u64 = 30;

/// Sleep between successful pages when the crawler is catching up
/// from cold. Polite-client rate-limit budget — the PLC directory
/// is a community resource.
const PAGE_BACKOFF: Duration = Duration::from_millis(250);

/// Sleep between *full crawls* once the worker has caught up to the
/// live edge. One pass per six hours catches new labelers without
/// hammering the PLC directory.
const INTER_CRAWL_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// One JSON record returned by `/export`.
///
/// The PLC log records DID operations chronologically; each line is
/// one [`PlcOpRecord`]. We only consume `did`, `createdAt`, and the
/// nested `operation` map.
#[derive(Debug, Deserialize)]
struct PlcOpRecord {
    /// The DID this operation applies to.
    did: String,
    /// Wall-clock the op was recorded (RFC 3339 / ISO 8601). Used as
    /// the pagination cursor.
    #[serde(rename = "createdAt")]
    created_at: String,
    /// The operation payload itself.
    operation: PlcOperation,
}

/// The operation payload inside a [`PlcOpRecord`].
///
/// Two variants matter:
///
///   * `type: "create"` — the legacy DID-create op (Nov 2022 - Apr 2023).
///     Has a single `service: "<pds-url>"` field; no labelers used the
///     legacy form, so we ignore these.
///   * `type: "plc_operation"` — the modern op. Has a `services` map
///     keyed by service id; we look for an `atproto_labeler` entry.
#[derive(Debug, Deserialize)]
struct PlcOperation {
    #[serde(default)]
    services: Option<serde_json::Value>,
}

/// Errors raised by the discovery worker.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Reading the cursor row at startup failed.
    #[error("failed to load plc_export_cursor row")]
    CursorLoad(#[source] sqlx::Error),
    /// Persisting the cursor failed. Treated as fatal because a missed
    /// flush turns into re-ingesting every op we just processed.
    #[error("failed to persist plc_export_cursor row")]
    CursorPersist(#[source] sqlx::Error),
    /// Persisting a discovered labeler failed.
    #[error("failed to insert discovered labeler {did}")]
    LabelerInsert {
        /// The DID whose insert failed.
        did: String,
        /// The underlying sqlx error.
        #[source]
        source: sqlx::Error,
    },
    /// The worker was cancelled via its token.
    #[error("discovery worker cancelled")]
    Cancelled,
}

/// One labeler discovered on the PLC log.
#[derive(Debug, Clone)]
struct DiscoveredLabeler {
    did: String,
    /// Bare hostname extracted from the service endpoint URL
    /// (e.g. `mod.bsky.app`), suitable for `upstream_labelers.hostname`.
    hostname: String,
}

/// Run the discovery worker for the process lifetime.
///
/// On startup the worker loads its persisted cursor and walks PLC
/// forward; when it catches up to the live edge it sleeps for
/// [`INTER_CRAWL_INTERVAL`] then re-walks the delta since the cursor.
/// The pattern matches the upstream-labels run-loop's "load cursor,
/// stream, persist cursor" discipline.
///
/// `notify` is a shared handle the supervisor task awaits; every time
/// a new labeler row is inserted into `upstream_labelers` we fire it
/// so a fresh consumer is spawned without a process restart.
///
/// # Errors
///
/// Propagates any of the [`DiscoveryError`] variants. The caller logs
/// and decides whether to retry or escalate. Frame-level errors
/// (malformed JSON line, single labeler insert failure) are caught
/// internally and logged at WARN; only cursor I/O is fatal.
pub async fn run(
    pool: PgPool,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) -> Result<(), DiscoveryError> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .user_agent("polaris-labeler-discovery/0.1 (+https://github.com/dollspace-gay/polaris)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let base_url = std::env::var("POLARIS_PLC_DIRECTORY_URL")
        .unwrap_or_else(|_| DEFAULT_PLC_BASE_URL.to_owned());

    tracing::info!(plc_base = %base_url, "labeler discovery worker starting");

    loop {
        // One crawl pass: walks pages until the PLC log is exhausted.
        let pass_result = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(DiscoveryError::Cancelled),
            r = crawl_one_pass(&pool, &http, &base_url, notify.as_ref()) => r,
        };
        match pass_result {
            Ok(stats) => {
                tracing::info!(
                    pages = stats.pages,
                    ops_seen = stats.ops_seen,
                    labelers_inserted = stats.labelers_inserted,
                    "labeler discovery pass complete; sleeping until next cycle",
                );
            }
            Err(DiscoveryError::Cancelled) => return Err(DiscoveryError::Cancelled),
            Err(err) => {
                tracing::warn!(error = %err, "labeler discovery pass errored; will retry");
            }
        }

        // Sleep between passes; cancel short-circuits the sleep.
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(DiscoveryError::Cancelled),
            () = tokio::time::sleep(INTER_CRAWL_INTERVAL) => {}
        }
    }
}

/// Summary of one pass through the PLC log.
#[derive(Debug, Default)]
struct PassStats {
    pages: u64,
    ops_seen: u64,
    labelers_inserted: u64,
}

/// Walk PLC export from the persisted cursor until the log is
/// exhausted (a page returns fewer than [`PAGE_SIZE`] records).
async fn crawl_one_pass(
    pool: &PgPool,
    http: &reqwest::Client,
    base_url: &str,
    notify: &Notify,
) -> Result<PassStats, DiscoveryError> {
    let mut after = load_cursor(pool).await?;
    let mut stats = PassStats::default();

    loop {
        let url = build_export_url(base_url, after.as_deref());
        let response = match http.get(&url).send().await {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(error = %err, url = %url, "PLC export request failed; aborting pass");
                return Ok(stats);
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                url = %url,
                "PLC export non-2xx; aborting pass",
            );
            return Ok(stats);
        }

        // JSON-Lines body. Streaming line-by-line would be slightly
        // more memory-efficient but the page is bounded to 1000 lines
        // and the response is sub-MB; reading whole body is fine.
        let body = match response.text().await {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(error = %err, "failed to read PLC export body; aborting pass");
                return Ok(stats);
            }
        };

        let mut lines_in_page: i32 = 0;
        let mut last_created_at: Option<String> = None;
        for line in body.lines() {
            if line.is_empty() {
                continue;
            }
            lines_in_page = lines_in_page.saturating_add(1);
            stats.ops_seen = stats.ops_seen.saturating_add(1);

            let record: PlcOpRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        line_preview = line.chars().take(120).collect::<String>(),
                        "malformed PLC export line; skipping",
                    );
                    continue;
                }
            };
            last_created_at = Some(record.created_at.clone());

            if let Some(labeler) = extract_labeler(&record) {
                match insert_discovered_labeler(pool, &labeler).await {
                    Ok(true) => {
                        stats.labelers_inserted = stats.labelers_inserted.saturating_add(1);
                        tracing::info!(
                            did = %labeler.did,
                            hostname = %labeler.hostname,
                            "discovered new labeler",
                        );
                        // Issue #183: kick off a one-shot fetch of
                        // the labeler's bsky-side profile (display
                        // name, handle, avatar). Detached: we don't
                        // block discovery on the AppView call. The
                        // result lands in `labeler_profiles` so
                        // the case-view's LEFT JOIN picks it up.
                        let pool_for_profile = pool.clone();
                        let did_for_profile = labeler.did.clone();
                        let http_for_profile = http.clone();
                        tokio::spawn(async move {
                            fetch_and_cache_profile(
                                &http_for_profile,
                                &pool_for_profile,
                                &did_for_profile,
                            )
                            .await;
                        });
                        // Wake the supervisor so it spawns a consumer
                        // for this row without waiting for the next
                        // poll cycle.
                        notify.notify_one();
                    }
                    Ok(false) => {
                        // Row already existed; no notify needed.
                    }
                    Err(err) => {
                        tracing::warn!(
                            did = %labeler.did,
                            error = %err,
                            "failed to persist discovered labeler; continuing",
                        );
                    }
                }
            }
        }

        stats.pages = stats.pages.saturating_add(1);

        if let Some(cursor) = last_created_at {
            after = Some(cursor.clone());
            persist_cursor(pool, &cursor, stats.labelers_inserted).await?;
        }

        // Live-edge detection: a short page means the PLC log is
        // exhausted (or close to it). Exit the pass; the caller
        // sleeps for INTER_CRAWL_INTERVAL before re-walking.
        if lines_in_page < PAGE_SIZE {
            break;
        }
        tokio::time::sleep(PAGE_BACKOFF).await;
    }

    Ok(stats)
}

/// Build the PLC export URL for a given cursor.
///
/// `None` (or an empty string) means "start at the beginning". The
/// PLC log is sorted ascending by `createdAt`, so omitting `after`
/// returns the earliest page.
fn build_export_url(base: &str, after: Option<&str>) -> String {
    let base = base.trim_end_matches('/');
    match after {
        Some(s) if !s.is_empty() => {
            let qs = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("count", &PAGE_SIZE.to_string())
                .append_pair("after", s)
                .finish();
            format!("{base}/export?{qs}")
        }
        _ => format!("{base}/export?count={PAGE_SIZE}"),
    }
}

/// Extract labeler-service data from a PLC operation record.
///
/// Returns `Some(DiscoveredLabeler)` iff the operation declares an
/// `atproto_labeler` service with a usable endpoint URL.
fn extract_labeler(record: &PlcOpRecord) -> Option<DiscoveredLabeler> {
    let services = record.operation.services.as_ref()?;
    let services_map = services.as_object()?;
    let labeler_entry = services_map.get("atproto_labeler")?;
    let endpoint = labeler_entry.get("endpoint")?.as_str()?;
    let hostname = endpoint_to_hostname(endpoint)?;
    Some(DiscoveredLabeler {
        did: record.did.clone(),
        hostname,
    })
}

/// Strip a URL down to bare hostname: `https://mod.bsky.app/` →
/// `mod.bsky.app`. Returns `None` for inputs we can't parse — those
/// rows are dropped rather than persisting a malformed hostname.
fn endpoint_to_hostname(endpoint: &str) -> Option<String> {
    let url = url::Url::parse(endpoint).ok()?;
    let host = url.host_str()?;
    if host.is_empty() {
        return None;
    }
    // Honour non-standard ports if the labeler runs one (test
    // environments do); the upstream-labels run-loop builds
    // `wss://{host}/xrpc/...` from this value.
    if let Some(port) = url.port() {
        Some(format!("{host}:{port}"))
    } else {
        Some(host.to_owned())
    }
}

/// Default bsky AppView base for the `app.bsky.labeler.getServices`
/// profile-enrichment call. Operators running against a non-default
/// AppView can override via the `POLARIS_APPVIEW_BASE_URL` env var.
const APPVIEW_BASE_URL: &str = "https://public.api.bsky.app";

/// Fetch a labeler's `(display_name, handle, description, avatar)`
/// via the bsky AppView and cache the result in `labeler_profiles`
/// (issue #183).
///
/// Best-effort: any failure (transport, non-2xx, JSON shape mismatch,
/// DB write) logs at WARN and returns without touching the cache.
/// The case-view falls back to rendering the raw DID for the
/// labeler in question; a later discovery pass will retry.
///
/// # Wire shape
///
/// `app.bsky.labeler.getServices?dids=<did>&detailed=true` returns
/// `{ views: [ { creator: { did, handle, displayName, avatar,
/// description } } ] }`. We pull all four fields from the nested
/// `creator` object.
pub(crate) async fn fetch_and_cache_profile(http: &reqwest::Client, pool: &PgPool, did: &str) {
    let appview =
        std::env::var("POLARIS_APPVIEW_BASE_URL").unwrap_or_else(|_| APPVIEW_BASE_URL.to_owned());
    // The `?dids=<did>` form requires a properly URL-encoded DID
    // because colons are reserved characters.
    let qs = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("dids", did)
        .append_pair("detailed", "true")
        .finish();
    let url = format!("{appview}/xrpc/app.bsky.labeler.getServices?{qs}");

    let resp = match http.get(&url).send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::debug!(
                did,
                error = %err,
                "labeler-profile fetch failed; cache miss persists",
            );
            return;
        }
    };
    if !resp.status().is_success() {
        tracing::debug!(
            did,
            status = %resp.status(),
            "labeler-profile fetch non-2xx; cache miss persists",
        );
        return;
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(err) => {
            tracing::debug!(did, error = %err, "labeler-profile JSON decode failed");
            return;
        }
    };
    let Some(view) = body
        .get("views")
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| arr.first())
    else {
        tracing::debug!(did, "labeler-profile getServices returned no view");
        return;
    };
    let creator = view.get("creator");
    let display_name = creator
        .and_then(|c| c.get("displayName"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let handle = creator
        .and_then(|c| c.get("handle"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty() && *s != "handle.invalid")
        .map(str::to_owned);
    let description = creator
        .and_then(|c| c.get("description"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let avatar_url = creator
        .and_then(|c| c.get("avatar"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    if let Err(err) = sqlx::query!(
        r#"
        INSERT INTO labeler_profiles
            (did, display_name, handle, description, avatar_url,
             fetched_at, refreshed_at, last_attempt_at)
        VALUES ($1, $2, $3, $4, $5, now(), now(), now())
        ON CONFLICT (did) DO UPDATE
        SET display_name = EXCLUDED.display_name,
            handle = EXCLUDED.handle,
            description = EXCLUDED.description,
            avatar_url = EXCLUDED.avatar_url,
            refreshed_at = now(),
            last_attempt_at = now()
        "#,
        did,
        display_name,
        handle,
        description,
        avatar_url,
    )
    .execute(pool)
    .await
    {
        tracing::warn!(
            did,
            error = %err,
            "labeler-profile cache write failed; will retry on next discovery hit",
        );
    } else {
        tracing::debug!(
            did,
            display_name = display_name.as_deref().unwrap_or(""),
            handle = handle.as_deref().unwrap_or(""),
            "labeler-profile cached",
        );
    }
}

/// Insert a discovered labeler into `upstream_labelers`.
///
/// Idempotent: rows we've already inserted are no-ops. If the
/// operator later disables a labeler (`enabled = FALSE`), discovery
/// does NOT re-enable it — the operator's intent wins. Hostname is
/// refreshed on conflict because labelers occasionally change
/// service endpoints.
///
/// Returns `Ok(true)` when a new row was inserted, `Ok(false)` when
/// the row already existed.
async fn insert_discovered_labeler(
    pool: &PgPool,
    labeler: &DiscoveredLabeler,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        INSERT INTO upstream_labelers (did, hostname, enabled)
        VALUES ($1, $2, TRUE)
        ON CONFLICT (did) DO UPDATE
        SET hostname = EXCLUDED.hostname,
            updated_at = now()
        WHERE upstream_labelers.hostname <> EXCLUDED.hostname
        RETURNING (xmax = 0) AS inserted
        "#,
        labeler.did,
        labeler.hostname,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some_and(|r| r.inserted.unwrap_or(false)))
}

/// Load the persisted PLC pagination cursor.
async fn load_cursor(pool: &PgPool) -> Result<Option<String>, DiscoveryError> {
    let row = sqlx::query!(
        r#"
        SELECT last_after FROM plc_export_cursor WHERE id = TRUE
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(DiscoveryError::CursorLoad)?;
    if row.last_after.is_empty() {
        Ok(None)
    } else {
        Ok(Some(row.last_after))
    }
}

/// Persist the pagination cursor after a successful page.
async fn persist_cursor(
    pool: &PgPool,
    cursor: &str,
    inserted_in_pass: u64,
) -> Result<(), DiscoveryError> {
    let inserted_i64 = i64::try_from(inserted_in_pass).unwrap_or(i64::MAX);
    sqlx::query!(
        r#"
        UPDATE plc_export_cursor
        SET last_after = $1,
            last_run_at = now(),
            total_labelers_discovered = total_labelers_discovered + $2
        WHERE id = TRUE
        "#,
        cursor,
        inserted_i64,
    )
    .execute(pool)
    .await
    .map_err(DiscoveryError::CursorPersist)?;
    Ok(())
}

// ── unit tests (no DB) ──────────────────────────────────────────────────

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
    fn endpoint_to_hostname_strips_scheme() {
        assert_eq!(
            endpoint_to_hostname("https://mod.bsky.app").as_deref(),
            Some("mod.bsky.app"),
        );
        assert_eq!(
            endpoint_to_hostname("https://mod.bsky.app/").as_deref(),
            Some("mod.bsky.app"),
        );
    }

    #[test]
    fn endpoint_to_hostname_preserves_port() {
        // Test-environment labelers sometimes bind a non-standard
        // port; the run-loop builds `wss://{host}:{port}/xrpc/...`
        // from this value so we keep the port.
        assert_eq!(
            endpoint_to_hostname("http://localhost:8443/labeler").as_deref(),
            Some("localhost:8443"),
        );
    }

    #[test]
    fn endpoint_to_hostname_rejects_garbage() {
        assert!(endpoint_to_hostname("").is_none());
        assert!(endpoint_to_hostname("not-a-url").is_none());
    }

    #[test]
    fn build_export_url_omits_after_for_empty_cursor() {
        assert_eq!(
            build_export_url("https://plc.directory", None),
            format!("https://plc.directory/export?count={PAGE_SIZE}"),
        );
        assert_eq!(
            build_export_url("https://plc.directory", Some("")),
            format!("https://plc.directory/export?count={PAGE_SIZE}"),
        );
    }

    #[test]
    fn build_export_url_url_encodes_cursor() {
        let url = build_export_url("https://plc.directory", Some("2023-04-11T17:29:51.242Z"));
        // The colon must be URL-encoded; otherwise the PLC service
        // sees `T17` as the start of a fragment and ignores the
        // timestamp entirely.
        assert!(url.contains("after=2023-04-11T17%3A29%3A51.242Z"));
    }

    #[test]
    fn build_export_url_trims_trailing_slash_on_base() {
        let with_slash = build_export_url("https://plc.directory/", None);
        let without = build_export_url("https://plc.directory", None);
        assert_eq!(with_slash, without);
    }

    #[test]
    fn extract_labeler_pulls_atproto_labeler_service() {
        let record: PlcOpRecord = serde_json::from_str(
            r#"{
                "did": "did:plc:ar7c4by46qjdydhdevvrndac",
                "createdAt": "2024-01-01T00:00:00.000Z",
                "operation": {
                    "services": {
                        "atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example"},
                        "atproto_labeler": {"type": "AtprotoLabeler", "endpoint": "https://mod.bsky.app"}
                    }
                }
            }"#,
        ).unwrap();
        let labeler = extract_labeler(&record).expect("should extract");
        assert_eq!(labeler.did, "did:plc:ar7c4by46qjdydhdevvrndac");
        assert_eq!(labeler.hostname, "mod.bsky.app");
    }

    #[test]
    fn extract_labeler_returns_none_for_non_labeler_op() {
        // Legacy `create` op (no services field at all).
        let record: PlcOpRecord = serde_json::from_str(
            r#"{
                "did": "did:plc:abc",
                "createdAt": "2022-11-17T00:35:16.391Z",
                "operation": {}
            }"#,
        )
        .unwrap();
        assert!(extract_labeler(&record).is_none());

        // Modern op but no atproto_labeler entry.
        let record: PlcOpRecord = serde_json::from_str(
            r#"{
                "did": "did:plc:abc",
                "createdAt": "2024-01-01T00:00:00.000Z",
                "operation": {
                    "services": {
                        "atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example"}
                    }
                }
            }"#,
        ).unwrap();
        assert!(extract_labeler(&record).is_none());
    }

    #[test]
    fn extract_labeler_returns_none_for_malformed_endpoint() {
        let record: PlcOpRecord = serde_json::from_str(
            r#"{
                "did": "did:plc:abc",
                "createdAt": "2024-01-01T00:00:00.000Z",
                "operation": {
                    "services": {
                        "atproto_labeler": {"type": "AtprotoLabeler", "endpoint": "not-a-url"}
                    }
                }
            }"#,
        )
        .unwrap();
        assert!(extract_labeler(&record).is_none());
    }
}
