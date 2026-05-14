//! [`ExposureTracker`] — moderator-facing exposure accounting (design.md §5.7).
//!
//! All access to the `moderator_exposure` and `moderator_exposure_settings`
//! tables goes through this type. The four read/write surfaces are:
//!
//! - [`ExposureTracker::record`] — increment today's counter atomically via
//!   `INSERT … ON CONFLICT DO UPDATE`. Called by the M4 audit-chain hook.
//! - [`ExposureTracker::status_for_me`] — moderator's own dashboard view.
//!   Returns total exposure for the day, the moderator's cap, the
//!   force-break threshold, and whether the threshold has fired.
//! - [`ExposureTracker::remaining_budget`] — routing-side query (issue #22).
//!   Returns `0` when the force-break threshold has fired so the router
//!   never assigns a graphic-content incident to an over-exposed moderator.
//! - [`ExposureTracker::aggregate_for_manager`] — privacy-gated aggregate
//!   visibility. **Returns empty when `consent` is false**, regardless of
//!   any other signal in the system.
//!
//! Setting writes ([`ExposureTracker::set_daily_cap`],
//! [`ExposureTracker::set_share_with_manager`]) UPSERT into
//! `moderator_exposure_settings` so a moderator without a settings row
//! still gets the documented defaults on every read.

use polaris_types::ModeratorId;
use sqlx::PgPool;

use super::WellnessError;

/// Documented defaults — see `00000000000009_exposure.sql` for the matching
/// SQL DEFAULT clauses. The two definitions must agree; the read paths
/// fall back to these constants when the moderator has no
/// `moderator_exposure_settings` row.
///
/// `DEFAULT_DAILY_CAP` is conservative — large enough that the typical
/// shift does not hit it, small enough that the force-break threshold
/// fires before a moderator silently burns out. Moderators can raise or
/// lower it via the `PUT /api/wellness/exposure/me/cap` endpoint.
pub const DEFAULT_DAILY_CAP: u32 = 50;

/// Default force-break threshold as a percentage of the daily cap. At
/// 90% the moderator gets a "wrap up the current case, then take a
/// break" prompt before the cap is fully consumed; the remaining 10%
/// buffer covers in-flight assignments without forcing a hard cut-over.
pub const DEFAULT_FORCE_BREAK_AT_PCT: u8 = 90;

/// Per-moderator exposure tracker.
///
/// Cloneable and `Send + Sync` — the underlying [`sqlx::PgPool`] is
/// internally `Arc`-shared, so cloning the tracker is cheap and the same
/// trait surface can be threaded into routers, services, and routing-time
/// directory loaders alongside the existing `Pg*Repo` handles.
#[derive(Debug, Clone)]
pub struct ExposureTracker {
    pool: PgPool,
}

/// Moderator's own exposure status for the current day.
///
/// Wire shape exposed at `GET /api/wellness/exposure/me`. All count fields
/// are `u32` (per the issue #23 forbidden-pattern checklist: no `f64`
/// payload values); `force_break_at_pct` is `u8` so the percentage fits in
/// one byte.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExposureStatus {
    /// The date the totals cover. Always `current_date` on the DB clock at
    /// query time; carried explicitly so the client can render "today" with
    /// the server's notion of day boundaries.
    pub day: chrono::NaiveDate,
    /// Sum of `count` across all categories for `day`.
    pub total: u32,
    /// The moderator's configured daily cap (or the default when no
    /// settings row exists).
    pub daily_cap: u32,
    /// Force-break threshold percentage of [`Self::daily_cap`].
    pub force_break_at_pct: u8,
    /// `true` iff `total >= daily_cap * force_break_at_pct / 100`. The
    /// frontend renders this as a "take a break" prompt; the router
    /// independently treats it as `remaining_budget == 0`.
    pub force_break_active: bool,
    /// `daily_cap - total`, saturated at 0. Returned as `0` whenever
    /// `force_break_active` is true so the routing path has one number to
    /// consult.
    pub remaining_budget: u32,
}

/// Per-category breakdown row in the manager-visible aggregate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CategoryExposure {
    /// Free-form category string as recorded via
    /// [`ExposureTracker::record`].
    pub category: String,
    /// Number of recorded events for the (moderator, today, category) cell.
    pub count: u32,
}

impl ExposureTracker {
    /// Construct an [`ExposureTracker`] over a Postgres pool.
    ///
    /// The pool is already internally `Arc`-shared by `sqlx`; cloning the
    /// tracker (or the pool) is cheap and reuses the same backing
    /// connections.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record an exposure event for `moderator_id` against `category`.
    ///
    /// Increments the `(moderator_id, current_date, category)` counter
    /// atomically via `INSERT … ON CONFLICT DO UPDATE`. The increment is a
    /// single SQL statement so concurrent records against the same cell
    /// are linearised by Postgres' row lock — no read-modify-write race in
    /// the application.
    ///
    /// # Errors
    ///
    /// Returns [`WellnessError::Database`] if the query fails (connection
    /// loss, FK violation when `moderator_id` does not match a row in
    /// `moderators`). FK violations surface as `Database` rather than
    /// `NotFound` so the caller does not have to disambiguate at the
    /// wellness layer — record-on-unknown-moderator is a system bug, not
    /// a user-input issue.
    pub async fn record(
        &self,
        moderator_id: ModeratorId,
        category: &str,
    ) -> Result<(), WellnessError> {
        sqlx::query!(
            r#"
            INSERT INTO moderator_exposure (moderator_id, day, category, count)
            VALUES ($1, current_date, $2, 1)
            ON CONFLICT (moderator_id, day, category)
            DO UPDATE SET count = moderator_exposure.count + 1
            "#,
            moderator_id.0,
            category,
        )
        .execute(&self.pool)
        .await
        .map_err(WellnessError::Database)?;
        Ok(())
    }

    /// Compute the moderator's own exposure status for the current day.
    ///
    /// Joins the day's `moderator_exposure` rollup with the moderator's
    /// settings (or the documented defaults when no settings row exists).
    /// The settings LEFT JOIN means a freshly-onboarded moderator without
    /// any settings row still gets a render-able status — falling back to
    /// [`DEFAULT_DAILY_CAP`] and [`DEFAULT_FORCE_BREAK_AT_PCT`].
    ///
    /// # Errors
    ///
    /// Returns [`WellnessError::Database`] on query failure.
    pub async fn status_for_me(
        &self,
        moderator_id: ModeratorId,
    ) -> Result<ExposureStatus, WellnessError> {
        let row = sqlx::query!(
            r#"
            SELECT
                current_date                                AS "day!: chrono::NaiveDate",
                COALESCE((
                    SELECT SUM(count)::bigint
                    FROM moderator_exposure
                    WHERE moderator_id = $1 AND day = current_date
                ), 0)                                       AS "total!: i64",
                COALESCE(s.daily_cap, $2)                   AS "daily_cap!: i32",
                COALESCE(s.force_break_at_pct, $3)          AS "force_break_at_pct!: i16"
            FROM (SELECT 1) AS dummy
            LEFT JOIN moderator_exposure_settings s
                ON s.moderator_id = $1
            "#,
            moderator_id.0,
            i32::try_from(DEFAULT_DAILY_CAP).unwrap_or(i32::MAX),
            i16::from(DEFAULT_FORCE_BREAK_AT_PCT),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(WellnessError::Database)?;

        // Coerce SQL-side i64/i32/i16 into the payload's unsigned types.
        // Bounds are enforced by the migration's CHECK constraints
        // (daily_cap > 0, force_break_at_pct in (0, 100]); the saturating
        // conversions are defence-in-depth so the API surface never panics
        // on a hypothetical out-of-range DB value.
        let total: u32 = u32::try_from(row.total).unwrap_or(u32::MAX);
        let daily_cap: u32 = u32::try_from(row.daily_cap).unwrap_or(DEFAULT_DAILY_CAP);
        let force_break_at_pct: u8 =
            u8::try_from(row.force_break_at_pct.max(0)).unwrap_or(DEFAULT_FORCE_BREAK_AT_PCT);

        Ok(status_from_parts(
            row.day,
            total,
            daily_cap,
            force_break_at_pct,
        ))
    }

    /// Compute the routing-time remaining budget for `moderator_id`.
    ///
    /// Returns `0` whenever [`ExposureStatus::force_break_active`] would be
    /// true; otherwise returns [`ExposureStatus::remaining_budget`]. The
    /// router uses this single `u32` to decide whether a moderator is
    /// eligible for graphic-content assignments (issue #22's
    /// `exposure_budget_remaining` field on [`crate::routing::ModeratorForRouting`]).
    ///
    /// # Errors
    ///
    /// Propagates [`WellnessError::Database`] from
    /// [`Self::status_for_me`].
    pub async fn remaining_budget(&self, moderator_id: ModeratorId) -> Result<u32, WellnessError> {
        let status = self.status_for_me(moderator_id).await?;
        Ok(if status.force_break_active {
            0
        } else {
            status.remaining_budget
        })
    }

    /// Aggregate the moderator's per-category exposure for manager view.
    ///
    /// **Privacy invariant.** When `consent` is `false` this method returns
    /// an empty vector regardless of any other state. The check happens
    /// before the SQL query so a `consent=false` call performs no DB I/O
    /// at all. Callers MUST pass the moderator's
    /// `moderator_exposure_settings.share_with_manager` value as `consent`;
    /// passing `true` without reading the flag is a privacy bug.
    ///
    /// # Errors
    ///
    /// Returns [`WellnessError::Database`] if the underlying query fails.
    /// A `consent=false` call is infallible.
    pub async fn aggregate_for_manager(
        &self,
        moderator_id: ModeratorId,
        consent: bool,
    ) -> Result<Vec<CategoryExposure>, WellnessError> {
        // Privacy-by-construction: short-circuit before any DB read. The
        // empty return is identical for "no consent" and "consent but
        // zero events", which is the design intent — managers see nothing
        // that distinguishes a non-consenting moderator from a quiet day.
        if !consent {
            return Ok(Vec::new());
        }

        let rows = sqlx::query!(
            r#"
            SELECT category AS "category!: String", count AS "count!: i32"
            FROM moderator_exposure
            WHERE moderator_id = $1 AND day = current_date
            ORDER BY category
            "#,
            moderator_id.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(WellnessError::Database)?;

        Ok(rows
            .into_iter()
            .map(|row| CategoryExposure {
                category: row.category,
                count: u32::try_from(row.count).unwrap_or(0),
            })
            .collect())
    }

    /// Update the moderator's daily exposure cap.
    ///
    /// UPSERTs into `moderator_exposure_settings` — a moderator without a
    /// prior row gets a freshly inserted row carrying their requested cap
    /// and the documented defaults for the other columns
    /// ([`DEFAULT_FORCE_BREAK_AT_PCT`], `share_with_manager = false`).
    ///
    /// # Errors
    ///
    /// Returns [`WellnessError::Database`] on query failure (including
    /// the migration's `daily_cap > 0` CHECK firing on a zero input).
    pub async fn set_daily_cap(
        &self,
        moderator_id: ModeratorId,
        cap: u32,
    ) -> Result<(), WellnessError> {
        // Saturate to `i32::MAX` so the `cap > i32::MAX` corner case still
        // round-trips through the column's INT type; bounds otherwise come
        // from the SQL CHECK constraint (`daily_cap > 0`) which will reject
        // a zero input as a Database error.
        let cap_i32: i32 = i32::try_from(cap).unwrap_or(i32::MAX);
        sqlx::query!(
            r#"
            INSERT INTO moderator_exposure_settings (moderator_id, daily_cap)
            VALUES ($1, $2)
            ON CONFLICT (moderator_id)
            DO UPDATE SET daily_cap = EXCLUDED.daily_cap, updated_at = now()
            "#,
            moderator_id.0,
            cap_i32,
        )
        .execute(&self.pool)
        .await
        .map_err(WellnessError::Database)?;
        Ok(())
    }

    /// Toggle the moderator's `share_with_manager` consent flag.
    ///
    /// UPSERTs into `moderator_exposure_settings`. The consent flag is the
    /// load-bearing invariant of §5.7: when `false`, no aggregate exposure
    /// data is visible to managers via [`Self::aggregate_for_manager`].
    /// Defaults to `false` so the moderator is opted out until they
    /// explicitly opt in.
    ///
    /// # Errors
    ///
    /// Returns [`WellnessError::Database`] on query failure.
    pub async fn set_share_with_manager(
        &self,
        moderator_id: ModeratorId,
        share: bool,
    ) -> Result<(), WellnessError> {
        sqlx::query!(
            r#"
            INSERT INTO moderator_exposure_settings (moderator_id, share_with_manager)
            VALUES ($1, $2)
            ON CONFLICT (moderator_id)
            DO UPDATE SET share_with_manager = EXCLUDED.share_with_manager,
                          updated_at = now()
            "#,
            moderator_id.0,
            share,
        )
        .execute(&self.pool)
        .await
        .map_err(WellnessError::Database)?;
        Ok(())
    }

    /// Read the moderator's current `share_with_manager` flag.
    ///
    /// Defaults to `false` when no settings row exists. Manager-view
    /// callers MUST read this through the tracker rather than infer it
    /// from any other surface — the consent is the gate for
    /// [`Self::aggregate_for_manager`] and must be passed straight through
    /// without an intermediate transformation.
    ///
    /// # Errors
    ///
    /// Returns [`WellnessError::Database`] on query failure.
    pub async fn share_with_manager(
        &self,
        moderator_id: ModeratorId,
    ) -> Result<bool, WellnessError> {
        let row = sqlx::query!(
            r#"
            SELECT share_with_manager AS "share_with_manager!: bool"
            FROM moderator_exposure_settings
            WHERE moderator_id = $1
            "#,
            moderator_id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(WellnessError::Database)?;
        Ok(row.is_some_and(|r| r.share_with_manager))
    }
}

/// Compose an [`ExposureStatus`] from the raw parts read from the DB.
///
/// Split out as a pure function so the force-break / remaining-budget
/// computation is unit-testable without a database. The forbidden-pattern
/// rule from issue #22 — "force-break logic is a pure function over
/// (`remaining_budget`, threshold), testable in isolation" — applies here
/// verbatim.
fn status_from_parts(
    day: chrono::NaiveDate,
    total: u32,
    daily_cap: u32,
    force_break_at_pct: u8,
) -> ExposureStatus {
    let force_break_threshold = force_break_threshold(daily_cap, force_break_at_pct);
    let force_break_active = total >= force_break_threshold;
    let remaining_budget = if force_break_active {
        0
    } else {
        daily_cap.saturating_sub(total)
    };
    ExposureStatus {
        day,
        total,
        daily_cap,
        force_break_at_pct,
        force_break_active,
        remaining_budget,
    }
}

/// Compute the integer threshold at which a force-break fires.
///
/// `daily_cap * pct / 100`, computed in `u64` to avoid mid-expression
/// overflow on a `u32::MAX` cap. Pct is clamped to `[0, 100]` (the CHECK
/// constraint already enforces this at the DB layer; the clamp is
/// defence-in-depth).
fn force_break_threshold(daily_cap: u32, pct: u8) -> u32 {
    let pct_clamped: u64 = u64::from(pct.min(100));
    let cap_u64: u64 = u64::from(daily_cap);
    let raw = cap_u64.saturating_mul(pct_clamped) / 100;
    u32::try_from(raw).unwrap_or(u32::MAX)
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
    use chrono::NaiveDate;

    fn mk_day() -> NaiveDate {
        // Use a fixed sentinel — the helper is a pure function so the
        // specific date is irrelevant; the tests assert on derived flags.
        NaiveDate::from_ymd_opt(2026, 5, 14).expect("valid date")
    }

    #[test]
    fn force_break_threshold_at_90_pct_of_50_is_45() {
        assert_eq!(force_break_threshold(50, 90), 45);
    }

    #[test]
    fn force_break_threshold_zero_pct_is_zero() {
        assert_eq!(force_break_threshold(50, 0), 0);
    }

    #[test]
    fn force_break_threshold_one_hundred_pct_is_cap() {
        assert_eq!(force_break_threshold(50, 100), 50);
    }

    #[test]
    fn force_break_threshold_overflow_saturates() {
        // u32::MAX * 100 would overflow in u32; computation is in u64.
        assert!(force_break_threshold(u32::MAX, 100) > 0);
    }

    #[test]
    fn status_inactive_below_threshold() {
        let s = status_from_parts(mk_day(), 10, 50, 90);
        assert!(!s.force_break_active);
        assert_eq!(s.remaining_budget, 40);
        assert_eq!(s.daily_cap, 50);
        assert_eq!(s.force_break_at_pct, 90);
    }

    #[test]
    fn status_active_at_threshold_zeroes_budget() {
        // 45 = 50 * 90 / 100 → exactly the threshold, force-break fires.
        let s = status_from_parts(mk_day(), 45, 50, 90);
        assert!(s.force_break_active);
        assert_eq!(s.remaining_budget, 0);
    }

    #[test]
    fn status_active_above_threshold() {
        let s = status_from_parts(mk_day(), 60, 50, 90);
        assert!(s.force_break_active);
        assert_eq!(s.remaining_budget, 0);
    }

    #[test]
    fn status_zero_pct_threshold_always_active() {
        // A 0% threshold means any exposure forces a break.
        let s = status_from_parts(mk_day(), 0, 50, 0);
        assert!(s.force_break_active);
        assert_eq!(s.remaining_budget, 0);
    }

    #[test]
    fn category_exposure_serialises_to_snake_case_payload() {
        let row = CategoryExposure {
            category: "graphic".to_owned(),
            count: 7,
        };
        let json = serde_json::to_string(&row).expect("serialize");
        assert_eq!(json, r#"{"category":"graphic","count":7}"#);
    }
}
