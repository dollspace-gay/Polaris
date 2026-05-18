//! Background worker that fires scheduled takedowns when their
//! `execute_at` passes (L1 / Ozone-parity
//! `tools.ozone.moderation.defs#scheduleTakedownEvent`).
//!
//! Polls `scheduled_takedowns` every [`POLL_INTERVAL`] for rows whose
//! `execute_at <= now()` and are neither already-executed nor
//! cancelled. For each such row, inserts a fresh `actions` row of
//! `kind = takedown` carrying the frozen-at-schedule reasoning,
//! `policy_refs`, and `label_value`, then marks the schedule's
//! `executed_at` + `executed_action_id` so the audit trail links
//! schedule to enforcement.
//!
//! # Atomicity
//!
//! Each schedule's transition (PENDING → EXECUTED) is done inside a
//! single transaction that BOTH inserts the action row AND updates
//! the schedule row. If either step fails the transaction rolls back
//! and the worker will retry on the next poll — so a partial
//! failure never leaves a schedule "stuck" with an action half-
//! written.
//!
//! # Skip-locked semantics
//!
//! `SELECT ... FOR UPDATE SKIP LOCKED` lets multiple Polaris replicas
//! drain the same queue without stepping on each other. Each replica
//! takes a row, holds the lock for the transaction, and another
//! replica can claim the next pending row.
//!
//! # Forbidden patterns
//!
//! - No `unwrap()`/`expect()` outside `#[cfg(test)]`.
//! - No tight-loop on persistent failure — poll-interval bounds the
//!   retry cadence at 60s.
//! - No `unsafe`.

use std::time::Duration;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// How often the worker checks for due schedules. 60s is the floor
/// for moderator-perceptible latency (a takedown scheduled for "now"
/// fires within a minute) while keeping the DB poll rate low.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum number of schedules to drain per poll cycle. Bounds the
/// worker's worst-case work-burst when many schedules come due at
/// once (e.g., after a process restart catching up).
const MAX_PER_CYCLE: i64 = 50;

/// Run the worker for the process lifetime.
///
/// The loop wakes every [`POLL_INTERVAL`] OR immediately when
/// `cancel` is fired. On cancel, returns cleanly.
pub async fn run(pool: PgPool, cancel: CancellationToken) {
    tracing::info!(
        poll_interval_s = POLL_INTERVAL.as_secs(),
        max_per_cycle = MAX_PER_CYCLE,
        "scheduled-takedown worker starting",
    );
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::info!("scheduled-takedown worker cancelled");
                return;
            }
            () = tokio::time::sleep(POLL_INTERVAL) => {}
        }
        drain_due_schedules(&pool).await;
    }
}

/// One poll cycle: drain up to [`MAX_PER_CYCLE`] due schedules.
async fn drain_due_schedules(pool: &PgPool) {
    let due = match fetch_due_ids(pool).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "scheduled-takedown worker: due-list query failed; retrying next tick",
            );
            return;
        }
    };
    if due.is_empty() {
        return;
    }
    tracing::info!(due = due.len(), "scheduled-takedown worker firing");
    for id in due {
        if let Err(err) = execute_one(pool, id).await {
            tracing::warn!(
                schedule_id = %id,
                error = %err,
                "scheduled-takedown execute failed; will retry next tick",
            );
        }
    }
}

/// Find the next batch of schedules whose `execute_at` has passed and
/// are still PENDING.
///
/// `SKIP LOCKED` lets concurrent replicas split the work — each
/// replica grabs different rows so we never double-fire a schedule.
async fn fetch_due_ids(pool: &PgPool) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT id
        FROM scheduled_takedowns
        WHERE execute_at <= now()
          AND executed_at IS NULL
          AND cancelled_at IS NULL
        ORDER BY execute_at
        LIMIT $1
        FOR UPDATE SKIP LOCKED
        "#,
        MAX_PER_CYCLE,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.id).collect())
}

/// Execute one schedule: INSERT the `actions` row + UPDATE the
/// schedule's terminal columns, both inside one transaction.
///
/// The UPDATE's WHERE clause re-asserts the PENDING invariant so a
/// race against `cancel()` cannot result in a double terminal state.
async fn execute_one(pool: &PgPool, id: uuid::Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Read the frozen-at-schedule context.
    let sched = sqlx::query!(
        r#"
        SELECT subject_id, incident_id, created_by,
               reasoning, policy_refs, label_value
        FROM scheduled_takedowns
        WHERE id = $1
          AND executed_at IS NULL
          AND cancelled_at IS NULL
        FOR UPDATE
        "#,
        id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(sched) = sched else {
        // Race-loser path: another replica beat us to it OR the
        // operator cancelled in the gap. Either way, no-op.
        tx.rollback().await?;
        return Ok(());
    };

    // Compute the reversible_until cutoff using the same 24h window
    // the manual submit_action path uses (design.md §5.5).
    let reversible_until = chrono::Utc::now() + chrono::Duration::hours(24);

    // INSERT the materialised takedown row.
    let action = sqlx::query!(
        r#"
        INSERT INTO actions
            (incident_id, subject_id, moderator_id, kind,
             label_value, reasoning, policy_refs, reversible_until)
        VALUES ($1, $2, $3, 'takedown', $4, $5, $6, $7)
        RETURNING id
        "#,
        sched.incident_id,
        sched.subject_id,
        sched.created_by,
        sched.label_value,
        sched.reasoning,
        &sched.policy_refs,
        reversible_until,
    )
    .fetch_one(&mut *tx)
    .await?;

    // Mark the schedule as executed.
    sqlx::query!(
        r#"
        UPDATE scheduled_takedowns
        SET executed_at = now(),
            executed_action_id = $1
        WHERE id = $2
          AND executed_at IS NULL
          AND cancelled_at IS NULL
        "#,
        action.id,
        id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        schedule_id = %id,
        action_id = %action.id,
        subject_id = %sched.subject_id,
        "scheduled takedown materialised as actions row",
    );
    metrics::counter!("polaris_scheduled_takedowns_fired_total").increment(1);
    Ok(())
}
