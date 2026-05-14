//! Reporter-reputation scoring (issue #37, design.md §9.3).
//!
//! Mitigates threat T3: adversaries gaming the report system to weaponize
//! moderation against innocents. The mitigation is a per-reporter
//! historical-credibility score, weighted into the pattern engine and
//! surfaced in the case-view DTO so a moderator can see "this subject has
//! 10 reports, 6 of them from reporters with a strong track record."
//!
//! # Layout
//!
//! - [`score`] — the pure scoring function and the [`ReputationScore`]
//!   newtype. No I/O, no database, no async — unit-testable in isolation.
//! - This module — the [`ReputationProvider`] trait + the
//!   [`PgReputationProvider`] Postgres implementation. Wires record-keeping
//!   ([`PgReputationProvider::record_report_filed`],
//!   [`PgReputationProvider::record_action`]) and read-side scoring
//!   ([`ReputationProvider::score_for`]) over `reporter_stats` from
//!   migration `00000000000020_reporter_stats.sql`.
//!
//! # Pattern-engine integration shape
//!
//! Pattern detectors that aggregate reports should weight each report by
//! its reporter's score. Today's integration site is the report-volume
//! panel on the dashboard (`api/dashboard.rs::build_report_volume`); deeper
//! detector-side wiring (the in-process `MemoryAnomalyDetector` in
//! `pattern::anomaly`) is filed as the M2 follow-up. The
//! [`ReputationProvider`] trait keeps the interface stable so the future
//! wiring is a constructor swap, not a redesign.

use std::future::Future;

use chrono::{DateTime, Utc};
use polaris_types::ActionKind;
use sqlx::PgPool;

pub mod score;

pub use score::{ReporterStats, ReputationError, ReputationParams, ReputationScore, reputation};

/// Read-side abstraction over the reporter-reputation store.
///
/// Pattern-engine call sites depend on this trait — the cached-score path
/// is a single `SELECT … LIMIT 1` against `reporter_stats` and falls back
/// to [`ReputationScore::neutral`] when no row exists. Tests use a
/// fake-data implementation; the production wiring uses
/// [`PgReputationProvider`].
pub trait ReputationProvider: Send + Sync {
    /// Look up the reputation score for `did`.
    ///
    /// Returns [`ReputationScore::neutral`] when the reporter has no stats
    /// row (a never-before-seen reporter is by definition prior-neutral).
    /// Other failures (database errors, encoding faults) surface as
    /// [`ReputationError`].
    fn score_for(
        &self,
        did: &str,
    ) -> impl Future<Output = Result<ReputationScore, ReputationError>> + Send;
}

/// Postgres-backed [`ReputationProvider`].
///
/// Owns a [`PgPool`] (cheap clone; the pool is internally `Arc`-shared) and
/// a [`ReputationParams`] value (cheap copy). Cloning the provider is
/// `Arc::clone` on the pool plus a `Copy` of the params — every call site
/// can hold its own handle.
#[derive(Debug, Clone)]
pub struct PgReputationProvider {
    pool: PgPool,
    params: ReputationParams,
}

impl PgReputationProvider {
    /// Build a [`PgReputationProvider`] over the given pool and params.
    ///
    /// # Errors
    ///
    /// Returns [`ReputationError::OutOfRange`] when `params.half_life_days`
    /// is non-positive or `prior_actioned + prior_dismissed` is
    /// non-positive — degenerate configurations the pure function defends
    /// against but operators should never knowingly set.
    pub fn new(pool: PgPool, params: ReputationParams) -> Result<Self, ReputationError> {
        if !params.half_life_days.is_finite() || params.half_life_days <= 0.0 {
            return Err(ReputationError::OutOfRange {
                value: params.half_life_days,
            });
        }
        if !params.prior_actioned.is_finite()
            || params.prior_actioned <= 0.0
            || !params.prior_dismissed.is_finite()
            || params.prior_dismissed <= 0.0
        {
            return Err(ReputationError::OutOfRange {
                value: params.prior_actioned + params.prior_dismissed,
            });
        }
        Ok(Self { pool, params })
    }

    /// Borrow the configured params (used by tests and observability).
    #[must_use]
    pub fn params(&self) -> &ReputationParams {
        &self.params
    }

    /// Record a report filed by `did`, against an external executor.
    ///
    /// Upserts the `reporter_stats` row (filed counter + `last_active`)
    /// and refreshes the cached score, both against the supplied executor
    /// so the caller can compose this side-effect with their own
    /// transaction (e.g. the report-insert path commits both the report
    /// row and the stats update atomically).
    ///
    /// # Errors
    ///
    /// Surfaces sqlx errors via [`ReputationError::Db`].
    pub async fn record_report_filed_with(
        &self,
        conn: &mut sqlx::PgConnection,
        did: &str,
    ) -> Result<(), ReputationError> {
        // Borrow-checker note: we need three sequential queries against
        // the same connection, so we pass `&mut *conn` to each in turn.
        let now = Utc::now();
        sqlx::query!(
            r#"
            INSERT INTO reporter_stats (did, reports_filed, first_seen, last_active)
            VALUES ($1, 1, $2, $2)
            ON CONFLICT (did) DO UPDATE
                SET reports_filed = reporter_stats.reports_filed + 1,
                    last_active   = EXCLUDED.last_active
            "#,
            did,
            now,
        )
        .execute(&mut *conn)
        .await?;
        let stats = fetch_stats(&mut *conn, did).await?;
        let score = reputation(&stats, now, &self.params);
        update_cached_score(&mut *conn, did, score, now).await?;
        Ok(())
    }

    /// Owned-tx convenience for [`Self::record_report_filed_with`].
    ///
    /// Opens its own transaction against the held pool. Use this from
    /// call sites that aren't already inside a transaction.
    ///
    /// # Errors
    ///
    /// Surfaces sqlx errors via [`ReputationError::Db`].
    pub async fn record_report_filed(&self, did: &str) -> Result<(), ReputationError> {
        let mut tx = self.pool.begin().await?;
        self.record_report_filed_with(&mut tx, did).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Record an action committed against a report from `did`, against an
    /// external executor.
    ///
    /// `kind` determines the counter:
    ///
    /// - [`ActionKind::Label`] / [`ActionKind::Takedown`] → `reports_actioned += 1`
    /// - [`ActionKind::NoAction`] → `reports_dismissed += 1` (the "dismissed" path)
    /// - other kinds → no-op (Mute, Warn, Escalate, Reverse are neither
    ///   credit nor demerit for the reporter; an Escalate may later
    ///   produce a Label/Takedown/NoAction which is what we score on).
    ///
    /// The cached score is recomputed against the supplied executor so
    /// the caller can compose with their own transaction.
    ///
    /// # Errors
    ///
    /// Surfaces sqlx errors via [`ReputationError::Db`].
    pub async fn record_action_with(
        &self,
        conn: &mut sqlx::PgConnection,
        did: &str,
        kind: ActionKind,
    ) -> Result<(), ReputationError> {
        let increment = match kind {
            ActionKind::Label | ActionKind::Takedown => ActionIncrement::Actioned,
            ActionKind::NoAction => ActionIncrement::Dismissed,
            ActionKind::Mute | ActionKind::Warn | ActionKind::Escalate | ActionKind::Reverse => {
                return Ok(());
            }
        };
        let now = Utc::now();
        match increment {
            ActionIncrement::Actioned => {
                sqlx::query!(
                    r#"
                    INSERT INTO reporter_stats (did, reports_actioned, first_seen, last_active)
                    VALUES ($1, 1, $2, $2)
                    ON CONFLICT (did) DO UPDATE
                        SET reports_actioned = reporter_stats.reports_actioned + 1,
                            last_active      = EXCLUDED.last_active
                    "#,
                    did,
                    now,
                )
                .execute(&mut *conn)
                .await?;
            }
            ActionIncrement::Dismissed => {
                sqlx::query!(
                    r#"
                    INSERT INTO reporter_stats (did, reports_dismissed, first_seen, last_active)
                    VALUES ($1, 1, $2, $2)
                    ON CONFLICT (did) DO UPDATE
                        SET reports_dismissed = reporter_stats.reports_dismissed + 1,
                            last_active       = EXCLUDED.last_active
                    "#,
                    did,
                    now,
                )
                .execute(&mut *conn)
                .await?;
            }
        }
        let stats = fetch_stats(&mut *conn, did).await?;
        let score = reputation(&stats, now, &self.params);
        update_cached_score(&mut *conn, did, score, now).await?;
        Ok(())
    }

    /// Owned-tx convenience for [`Self::record_action_with`].
    ///
    /// # Errors
    ///
    /// Surfaces sqlx errors via [`ReputationError::Db`].
    pub async fn record_action(&self, did: &str, kind: ActionKind) -> Result<(), ReputationError> {
        let mut tx = self.pool.begin().await?;
        self.record_action_with(&mut tx, did, kind).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Read the stats row for `did`.
    ///
    /// # Errors
    ///
    /// Returns [`ReputationError::UnknownReporter`] when no row exists; other
    /// failures surface via [`ReputationError::Db`].
    pub async fn get_stats(&self, did: &str) -> Result<ReporterStats, ReputationError> {
        let mut conn = self.pool.acquire().await?;
        fetch_stats(&mut *conn, did).await
    }
}

/// Discriminator for which counter [`PgReputationProvider::record_action`]
/// bumps. Kept private so the public surface only carries [`ActionKind`].
#[derive(Debug, Clone, Copy)]
enum ActionIncrement {
    Actioned,
    Dismissed,
}

impl ReputationProvider for PgReputationProvider {
    /// Look up the cached score for `did`. On a cache miss (no row) we
    /// return [`ReputationScore::neutral`] rather than surfacing an error —
    /// a never-seen reporter is by definition prior-neutral and asking
    /// the caller to handle the "unknown reporter" case at every read
    /// site would propagate an Option through the pattern-engine
    /// integration for no benefit.
    ///
    /// The cached value can be stale relative to `last_active` — the
    /// design accepts that. The recompute on every record-keeping path
    /// keeps the cache fresh whenever the reporter is active; for a
    /// reporter idle long enough for time-decay to matter, the cached
    /// score under-weights the decay by at most one observation window.
    async fn score_for(&self, did: &str) -> Result<ReputationScore, ReputationError> {
        let row = sqlx::query!(
            r#"
            SELECT cached_score
            FROM reporter_stats
            WHERE did = $1
            "#,
            did,
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(ReputationScore::neutral());
        };
        ReputationScore::new(row.cached_score)
    }
}

/// Read a `reporter_stats` row through any sqlx executor.
///
/// `&mut *tx`-style executors share the same shape; this helper avoids
/// duplicating the column list at each call site.
async fn fetch_stats<'e, E>(executor: E, did: &str) -> Result<ReporterStats, ReputationError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query!(
        r#"
        SELECT did, reports_filed, reports_actioned, reports_dismissed,
               first_seen, last_active
        FROM reporter_stats
        WHERE did = $1
        "#,
        did,
    )
    .fetch_optional(executor)
    .await?;
    let row = row.ok_or_else(|| ReputationError::UnknownReporter {
        did: did.to_owned(),
    })?;
    Ok(ReporterStats {
        did: row.did,
        reports_filed: row.reports_filed,
        reports_actioned: row.reports_actioned,
        reports_dismissed: row.reports_dismissed,
        first_seen: row.first_seen,
        last_active: row.last_active,
    })
}

/// Write the freshly-computed cached score into the row.
///
/// Separated from the upsert paths so the recompute is one statement,
/// readable on its own, and the same shape for the actioned / dismissed /
/// filed branches.
async fn update_cached_score<'e, E>(
    executor: E,
    did: &str,
    score: ReputationScore,
    at: DateTime<Utc>,
) -> Result<(), ReputationError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query!(
        r#"
        UPDATE reporter_stats
        SET cached_score = $2,
            cached_at    = $3
        WHERE did = $1
        "#,
        did,
        score.into_inner(),
        at,
    )
    .execute(executor)
    .await?;
    Ok(())
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

    // The Pg-provider constructor takes a `PgPool`; constructing a
    // `PgPool` (even via `connect_lazy`) requires a running Tokio
    // runtime because the pool eagerly spawns a maintenance task. Use
    // `#[tokio::test]` so the constructor-validation tests can build
    // their placeholder pool without panicking on the runtime check.

    #[tokio::test]
    async fn pg_provider_rejects_zero_half_life() {
        let dummy_pool = unsafe_test_pool_placeholder();
        let err = PgReputationProvider::new(
            dummy_pool,
            ReputationParams {
                prior_actioned: 1.0,
                prior_dismissed: 1.0,
                half_life_days: 0.0,
            },
        )
        .expect_err("zero half-life should be rejected");
        assert!(matches!(err, ReputationError::OutOfRange { .. }));
    }

    #[tokio::test]
    async fn pg_provider_rejects_negative_prior() {
        let dummy_pool = unsafe_test_pool_placeholder();
        let err = PgReputationProvider::new(
            dummy_pool,
            ReputationParams {
                prior_actioned: -1.0,
                prior_dismissed: 1.0,
                half_life_days: 90.0,
            },
        )
        .expect_err("negative prior should be rejected");
        assert!(matches!(err, ReputationError::OutOfRange { .. }));
    }

    #[tokio::test]
    async fn pg_provider_accepts_default_params() {
        let dummy_pool = unsafe_test_pool_placeholder();
        let provider = PgReputationProvider::new(dummy_pool, ReputationParams::default())
            .expect("default params are valid");
        assert!((provider.params().prior_actioned - 1.0).abs() < f32::EPSILON);
        assert!((provider.params().prior_dismissed - 1.0).abs() < f32::EPSILON);
        assert!((provider.params().half_life_days - 90.0).abs() < f32::EPSILON);
    }

    /// Construct a [`PgPool`] handle that is never connected against —
    /// the constructor tests above only exercise param validation, which
    /// runs before any database round-trip. `PgPool::connect_lazy` builds
    /// the handle without contacting Postgres, so this is safe.
    fn unsafe_test_pool_placeholder() -> PgPool {
        // `connect_lazy` does not perform I/O — it parses the URL into
        // connect options and returns a pool that will dial on first use.
        // The constructor tests above never call into the pool, so no
        // dial ever happens.
        PgPool::connect_lazy("postgres://postgres:postgres@127.0.0.1:55432/never_connected")
            .expect("connect_lazy parses a well-formed URL")
    }
}
