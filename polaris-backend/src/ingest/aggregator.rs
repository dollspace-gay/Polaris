//! Incident-aggregation worker (issue #75, T4 mitigation).
//!
//! `design.md` §9 #4 — "a thousand identical reports become one incident with
//! a thousand reporters." The aggregator is the background task that walks
//! freshly-inserted reports whose `incident_id IS NULL`, groups them by
//! `subject_id`, and either attaches each batch to an existing open incident
//! (created within the configured time window) or opens a new one.
//!
//! # Worker shape
//!
//! Follows the same conventions as the other workers in [`crate::ingest`] and
//! [`crate::evidence::worker`]:
//!
//! 1. **Single-task ownership.** The aggregator holds the `PgPool` by value;
//!    no `Arc<Mutex<…>>` is needed because the per-tick state never escapes
//!    the function.
//! 2. **`SELECT … FOR UPDATE SKIP LOCKED`** on the report claim path so
//!    multiple aggregator replicas can drain in parallel without stepping on
//!    each other.
//! 3. **`tokio::time::sleep`** between batches — never a tight loop.
//! 4. **Typed errors** via [`AggregatorError`] (`thiserror`-derived); the
//!    `run` loop swallows them with a WARN so a transient DB failure does
//!    not abort the worker.
//!
//! # CSAM-priority bypass under flood
//!
//! When a [`polaris_types::RoutingCategory::Csam`] (or `Csem`) report attaches
//! to a fresh incident, the aggregator marks the incident as
//! [`polaris_types::Severity::Critical`]. The routing service
//! ([`crate::routing::service::RoutingService::build_snapshot`]) already
//! routes `Severity::Critical` incidents through the CSAM cascade —
//! [`crate::routing::RoutingCategory::Csam`] — so the trained-moderator queue
//! gets the CSAM signal regardless of how deep the spam-flood backlog grows.
//! A CSAM report attaching to an existing non-critical incident promotes
//! that incident's severity in the same transaction.
//!
//! # Aggregation window
//!
//! Two reports against the same subject are grouped into the same incident
//! when the candidate incident's `opened_at` is within [`AggregatorConfig::window_secs`]
//! of `now()`. The default window is 24 hours — short enough that a brigade
//! that re-fires a day later opens a fresh case (so a separate moderator-
//! review surface), long enough that ordinary report bursts collapse to
//! one incident.
//!
//! An "open" incident for re-attachment purposes is one whose `status` is
//! `'open'` or `'in_review'`; `actioned` / `closed` / `escalated` incidents
//! are sealed and a fresh report against the same subject opens a new
//! incident. That mirrors the moderator's mental model — a closed case
//! stays closed.

use std::time::Duration;

use polaris_types::{RoutingCategory, Severity};
use sqlx::{PgPool, Postgres, Transaction};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Default time between drain ticks when the queue is empty.
///
/// 5 seconds matches [`crate::evidence::worker::DEFAULT_RETRY_BASE_SECS`]'s
/// idle-tick cadence — slow enough that an empty queue does not pound the
/// DB, fast enough that a fresh report attaches within an interactive-feel
/// horizon.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Default per-tick batch size.
///
/// Bounded so a single tick holds row-level locks for `O(batch_size)` reports
/// at a time; 256 is large enough to absorb a moderate flood within a few
/// ticks and small enough that transactions stay short.
pub const DEFAULT_BATCH_SIZE: i64 = 256;

/// Default aggregation window in seconds (24 hours).
///
/// A fresh report against a subject attaches to an open incident whose
/// `opened_at` is within this window of `now()`; otherwise the report opens
/// a new incident. 24h is the architect's default — see module-level docs.
pub const DEFAULT_WINDOW_SECS: i64 = 86_400;

/// Configuration for [`ReportAggregator`].
///
/// All fields are exposed via [`AppConfig::aggregator`] so operators can tune
/// the worker without re-compiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregatorConfig {
    /// Maximum number of un-aggregated reports to claim per tick.
    pub batch_size: i64,
    /// Wall-clock sleep between drain ticks.
    pub poll_interval: Duration,
    /// Width of the "attach to existing incident" window in seconds. A
    /// candidate open incident attached within `window_secs` of `now()`
    /// catches the report; otherwise a fresh incident is opened.
    pub window_secs: i64,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            poll_interval: Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS),
            window_secs: DEFAULT_WINDOW_SECS,
        }
    }
}

/// Errors raised by [`ReportAggregator`]'s tick path.
///
/// Library-grade `thiserror` enum — the worker's `run` loop catches every
/// `Err` and continues so a transient DB failure does not abort the task.
#[derive(Debug, thiserror::Error)]
pub enum AggregatorError {
    /// Underlying database error.
    #[error("database error")]
    Db(#[from] sqlx::Error),
}

/// Background worker that binds un-aggregated reports to incidents.
///
/// Hold this in `main()` by value and call [`ReportAggregator::run`] on a
/// `tokio::spawn`; the worker runs for the process lifetime. The loop
/// terminates only if the future is dropped (cancellation) — every fallible
/// path is folded into the `Result<i64, AggregatorError>` that the `run`
/// loop discards with a WARN.
#[derive(Debug, Clone)]
pub struct ReportAggregator {
    pool: PgPool,
    batch_size: i64,
    poll_interval: Duration,
    window_secs: i64,
}

impl ReportAggregator {
    /// Build a [`ReportAggregator`] from the supplied pool and configuration.
    #[must_use]
    pub fn new(pool: PgPool, cfg: AggregatorConfig) -> Self {
        // Guard against pathological configuration: zero / negative
        // batch sizes would either deadlock the worker or claim every row
        // in a single transaction. The minimum of 1 row per tick keeps
        // the loop semantics coherent even if an operator misconfigures.
        let batch_size = cfg.batch_size.max(1);
        // A zero window would never attach any report to an existing
        // incident, defeating the dedup contract entirely. Force a
        // minimum of one second.
        let window_secs = cfg.window_secs.max(1);
        Self {
            pool,
            batch_size,
            poll_interval: cfg.poll_interval,
            window_secs,
        }
    }

    /// Drain the queue forever.
    ///
    /// On a tick that successfully processes ≥ 1 report, the loop immediately
    /// re-ticks so a backlog drains as fast as the database allows. On an
    /// empty or failing tick it sleeps `poll_interval`. The loop never
    /// terminates by value (`!` return type); cancellation is via task
    /// abort.
    ///
    /// Per the rust-quality §10 rule, the loop's only `.await` points are
    /// the `tick` call and the `tokio::time::sleep` — no `std::sync::Mutex`
    /// guard crosses an await point and the future is cancel-safe at every
    /// suspension.
    pub async fn run(self) -> ! {
        info!(
            batch_size = self.batch_size,
            poll_interval_ms = u64::try_from(self.poll_interval.as_millis()).unwrap_or(u64::MAX),
            window_secs = self.window_secs,
            "report aggregator started",
        );
        loop {
            match self.tick().await {
                Ok(0) => {
                    // Empty queue → idle wait.
                    tokio::time::sleep(self.poll_interval).await;
                }
                Ok(n) => {
                    debug!(processed = n, "aggregator tick drained reports");
                    // Drained work → tick again immediately, no sleep.
                }
                Err(err) => {
                    warn!(error = ?err, "aggregator tick failed; retrying after poll interval");
                    tokio::time::sleep(self.poll_interval).await;
                }
            }
        }
    }

    /// Process one batch and return the number of reports aggregated.
    ///
    /// The tick runs as a single transaction:
    ///
    /// 1. Claim up to `batch_size` reports with `incident_id IS NULL` under
    ///    `FOR UPDATE SKIP LOCKED`.
    /// 2. For each unique subject in the batch, find an open incident in the
    ///    window or create a fresh one (CSAM signal in the batch drives the
    ///    new incident's severity to `Critical`; an existing non-critical
    ///    incident is promoted in the same transaction).
    /// 3. Update each report's `incident_id`. The trigger from migration 23
    ///    increments `incidents.report_count`.
    ///
    /// All work commits atomically; a single failure rolls back the tick and
    /// the run loop retries with a fresh transaction.
    ///
    /// # Errors
    ///
    /// Returns [`AggregatorError::Db`] on any underlying database failure.
    pub async fn tick(&self) -> Result<i64, AggregatorError> {
        let mut tx = self.pool.begin().await?;

        // Step 1: claim a batch. The ORDER BY created_at + FOR UPDATE SKIP
        // LOCKED pattern is the same one the evidence worker uses. The
        // `category` column is selected too so we can decide CSAM-promotion
        // without an extra round-trip.
        let claimed = sqlx::query!(
            r#"
            SELECT id, subject_id, category, created_at
            FROM reports
            WHERE incident_id IS NULL
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT $1
            "#,
            self.batch_size,
        )
        .fetch_all(&mut *tx)
        .await?;

        if claimed.is_empty() {
            // Nothing to do — commit (releasing the empty lock scope) and
            // return. Committing an empty tx is cheap and keeps the
            // happy path uniform.
            tx.commit().await?;
            return Ok(0);
        }

        // Step 2: group reports by subject. We preserve the per-subject
        // order so the first report's category drives a fresh-incident
        // severity decision deterministically.
        //
        // We resolve the incident id per-subject lazily; the first report
        // for a subject either attaches to an existing open incident
        // (within window) or opens a new one, and subsequent reports for
        // the same subject in this batch reuse that id.
        let mut updated: i64 = 0;
        let mut subject_incident: std::collections::HashMap<Uuid, Uuid> =
            std::collections::HashMap::new();
        let mut subject_csam_seen: std::collections::HashMap<Uuid, bool> =
            std::collections::HashMap::new();

        for report in &claimed {
            let subject_id = report.subject_id;
            let category_is_csam = is_csam_category(&report.category);

            // Per-subject incident resolution. We cannot use
            // `HashMap::entry().or_insert_with(...)` here because the
            // resolver is async — instead, branch on the cache miss
            // explicitly and insert the resolved id afterwards.
            if let Some(&cached_incident_id) = subject_incident.get(&subject_id) {
                // Subsequent CSAM report on the same subject in this
                // batch — promote the cached incident to Critical iff it
                // is not already. The flag avoids the redundant UPDATE
                // when we already promoted earlier in this batch.
                if category_is_csam {
                    let already = subject_csam_seen.get(&subject_id).copied().unwrap_or(false);
                    if !already {
                        promote_incident_to_critical(&mut tx, cached_incident_id).await?;
                        subject_csam_seen.insert(subject_id, true);
                    }
                }
            } else {
                // First time we see this subject in this batch: pick
                // an existing open incident in the window or open a
                // fresh one.
                let incident_id = self
                    .resolve_incident_for_subject(&mut tx, subject_id, category_is_csam)
                    .await?;
                subject_incident.insert(subject_id, incident_id);
                subject_csam_seen.insert(subject_id, category_is_csam);
            }

            // Re-fetch the (just-cached) incident id. The miss arm
            // above always inserts, so this is total — `let...else`
            // documents the invariant.
            let Some(&incident_id) = subject_incident.get(&subject_id) else {
                // Logically unreachable: every branch above inserts
                // into the map. We continue rather than panic to
                // honour the "no unwrap/expect in non-test code" rule.
                continue;
            };

            // Step 3: bind the report to the incident. The trigger from
            // migration 23 increments `incidents.report_count`.
            sqlx::query!(
                "UPDATE reports SET incident_id = $1 WHERE id = $2 AND created_at = $3",
                incident_id,
                report.id,
                report.created_at,
            )
            .execute(&mut *tx)
            .await?;
            updated += 1;
        }

        tx.commit().await?;
        Ok(updated)
    }

    /// Find an open incident for `subject_id` in the configured window, or
    /// open a new one. Operates inside the caller's transaction so the lock
    /// scope spans the whole tick.
    async fn resolve_incident_for_subject(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        subject_id: Uuid,
        category_is_csam: bool,
    ) -> Result<Uuid, AggregatorError> {
        // Try to attach to an existing open/in-review incident within the
        // window. ORDER BY opened_at DESC + LIMIT 1 picks the freshest
        // candidate; the partial index on (status, severity) is used by
        // the planner here.
        let window_secs = self.window_secs;
        let existing = sqlx::query!(
            r#"
            SELECT id, severity
            FROM incidents
            WHERE primary_subject = $1
              AND status IN ('open', 'in_review')
              AND opened_at >= now() - make_interval(secs => $2::double precision)
            ORDER BY opened_at DESC
            LIMIT 1
            "#,
            subject_id,
            // `make_interval(secs => …)` takes a double precision; we cast
            // the i64 → f64 explicitly to spell out the conversion.
            f64::from(i32::try_from(window_secs).unwrap_or(i32::MAX)),
        )
        .fetch_optional(&mut **tx)
        .await?;

        if let Some(row) = existing {
            // Promote severity to Critical iff this report is CSAM-class
            // and the existing incident is not already Critical. This is
            // the "CSAM-priority bypass under flood" surface — a CSAM
            // report attaching to an existing spam-cluster incident
            // upgrades that incident's routing severity.
            if category_is_csam && row.severity != Severity::Critical.as_str() {
                promote_incident_to_critical(tx, row.id).await?;
            }
            return Ok(row.id);
        }

        // No candidate — open a fresh incident. CSAM-class reports drive
        // Severity::Critical so the routing service's Critical → CSAM
        // mapping picks them up; everything else defaults to Medium.
        let severity = if category_is_csam {
            Severity::Critical
        } else {
            Severity::Medium
        };
        let row = sqlx::query!(
            r#"
            INSERT INTO incidents (primary_subject, severity, status)
            VALUES ($1, $2, 'open')
            RETURNING id
            "#,
            subject_id,
            severity.as_str(),
        )
        .fetch_one(&mut **tx)
        .await?;
        Ok(row.id)
    }
}

/// Promote an incident's severity to [`Severity::Critical`], idempotent.
///
/// The CHECK constraint on `incidents.severity` already constrains the
/// column to the polaris-types wire set; binding through `as_str()` keeps
/// the typed contract intact. The WHERE filter is a guard against the
/// trivial round-trip when the incident is already Critical.
async fn promote_incident_to_critical(
    tx: &mut Transaction<'_, Postgres>,
    incident_id: Uuid,
) -> Result<(), AggregatorError> {
    sqlx::query!(
        r#"
        UPDATE incidents
        SET severity = $1
        WHERE id = $2
          AND severity <> $1
        "#,
        Severity::Critical.as_str(),
        incident_id,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Whether a wire-form report category requires CSAM-priority routing.
///
/// Delegates to [`RoutingCategory::from_wire`] + the
/// [`RoutingCategory::requires_specialist_training`] flag so the closed
/// routing-side discriminator is the source of truth (per the
/// [`crate::routing`] module docs). Unknown wire forms collapse to
/// non-CSAM — the routing service's fallback handles them via the
/// generalist branch.
fn is_csam_category(wire: &str) -> bool {
    RoutingCategory::from_wire(wire).is_some_and(RoutingCategory::requires_specialist_training)
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
    fn aggregator_config_default_is_24h_window() {
        let cfg = AggregatorConfig::default();
        assert_eq!(cfg.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(
            cfg.poll_interval,
            Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS)
        );
        assert_eq!(cfg.window_secs, DEFAULT_WINDOW_SECS);
    }

    #[test]
    fn is_csam_category_matches_specialist_categories() {
        assert!(is_csam_category("csam"));
        assert!(is_csam_category("csem"));
        assert!(!is_csam_category("harassment"));
        assert!(!is_csam_category("spam"));
        assert!(!is_csam_category("unknown-wire-form"));
        assert!(!is_csam_category(""));
    }

    // Note: the `ReportAggregator::new` clamping behaviour is exercised
    // by the integration test `tests/incident_aggregator.rs`, which
    // boots a real Postgres container; we deliberately do not add a
    // unit test here because it would require a synthetic `PgPool`
    // and the rust-quality `expect_used` lint forbids constructing
    // one with `.expect(...)` outside test helpers we already have.
}
