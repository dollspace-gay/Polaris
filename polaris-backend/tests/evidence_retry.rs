//! Retry-with-backoff for failed evidence jobs (issue #69).
//!
//! Spins up Postgres 16 via testcontainers, applies the full migration
//! ladder (including #21 `evidence_retry`), and drives
//! [`EvidenceWorker::run_once`] against a controllable
//! [`EvidenceFetcher`] to verify:
//!
//! 1. **Failure schedules a retry.** A job whose fetcher returns an
//!    error transitions to `status='failed'` with `attempt_count=1`
//!    and `next_attempt_at` set to a wall-clock value strictly in the
//!    future (the row is *not* immediately reclaimed by the next tick).
//! 2. **Retry succeeds when due.** Pulling `next_attempt_at` into the
//!    past with a direct UPDATE and swapping in a succeeding fetcher
//!    makes the second tick reclaim the row, run it, and set
//!    `status='done'` with `attempt_count=2`.
//! 3. **Max-attempts is permanent.** Running the worker `max_attempts`
//!    times against an always-failing fetcher (with each
//!    `next_attempt_at` pulled into the past between ticks) ends with
//!    `status='failed'`, `attempt_count == max_attempts`, and
//!    `next_attempt_at IS NULL`. A subsequent tick must *not* drain
//!    the row (it stays permanently failed).
//!
//! Each test is in its own Postgres container so they cannot
//! interfere with each other on shared state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::Utc;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::evidence::{
    BlobStore, EvidenceFetcher, EvidenceFetcherError, EvidenceWorker, FetchedEvidence,
    InMemoryBlobStore,
};
use polaris_backend::repo::{
    self, ActionRepo, IncidentRepo, PgActionRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{
    ActionKind, AtUri, Did, IncidentStatus, ModeratorId, PolicyId, Severity, SubjectKind,
};
use proto_blue::lex_data::LexValue;
use proto_blue::repo::BlockMap;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn insert_moderator(pool: &sqlx::PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(ModeratorId(row.id))
}

/// Always-failing fetcher.
#[derive(Debug, Clone)]
struct AlwaysFailFetcher;

impl EvidenceFetcher for AlwaysFailFetcher {
    fn fetch_record_with_proof<'a>(
        &'a self,
        _subject_uri: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<FetchedEvidence, EvidenceFetcherError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Err(EvidenceFetcherError::Upstream {
                message: "synthetic failure for #69 retry path".into(),
            })
        })
    }
}

/// Synthetic succeeding fetcher (3 blocks + a root).
#[derive(Debug, Clone)]
struct SyntheticFetcher {
    root_cid: proto_blue::lex_data::Cid,
    blocks: BlockMap,
}

impl SyntheticFetcher {
    fn new() -> Self {
        let mut blocks = BlockMap::new();
        let root = blocks
            .add_value(&LexValue::String("signed-commit-root".into()))
            .expect("encode root block");
        let _proof_a = blocks
            .add_value(&LexValue::String("mst-proof-a".into()))
            .expect("encode proof a");
        let _proof_b = blocks
            .add_value(&LexValue::String("mst-proof-b".into()))
            .expect("encode proof b");
        let _record = blocks
            .add_value(&LexValue::String("record-block".into()))
            .expect("encode record");
        Self {
            root_cid: root,
            blocks,
        }
    }
}

impl EvidenceFetcher for SyntheticFetcher {
    fn fetch_record_with_proof<'a>(
        &'a self,
        _subject_uri: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<FetchedEvidence, EvidenceFetcherError>>
                + Send
                + 'a,
        >,
    > {
        let root = self.root_cid.clone();
        let blocks = self.blocks.clone();
        Box::pin(async move {
            Ok(FetchedEvidence {
                root_cid: root,
                blocks,
            })
        })
    }
}

/// Fetcher whose behaviour can be toggled at runtime. Used to drive
/// the "fail, then succeed" retry-then-recover transition without
/// constructing two `EvidenceWorker`s.
#[derive(Debug)]
struct ToggleFetcher {
    succeed: AtomicBool,
    succeeding: SyntheticFetcher,
}

impl ToggleFetcher {
    fn new_failing() -> Self {
        Self {
            succeed: AtomicBool::new(false),
            succeeding: SyntheticFetcher::new(),
        }
    }

    fn set_succeed(&self, v: bool) {
        self.succeed.store(v, Ordering::SeqCst);
    }
}

impl EvidenceFetcher for ToggleFetcher {
    fn fetch_record_with_proof<'a>(
        &'a self,
        subject_uri: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<FetchedEvidence, EvidenceFetcherError>>
                + Send
                + 'a,
        >,
    > {
        if self.succeed.load(Ordering::SeqCst) {
            self.succeeding.fetch_record_with_proof(subject_uri)
        } else {
            Box::pin(async move {
                Err(EvidenceFetcherError::Upstream {
                    message: "ToggleFetcher: configured to fail".into(),
                })
            })
        }
    }
}

async fn seed_action_against_record(
    pool: &sqlx::PgPool,
) -> Result<uuid::Uuid, Box<dyn std::error::Error>> {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let action_repo = PgActionRepo::new(pool.clone());

    let subject_uri = format!("at://did:plc:abc{}/app.bsky.feed.post/3l1", Uuid::new_v4());
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new("did:plc:abc")),
            uri: Some(AtUri::new(&subject_uri)),
            created_at: Utc::now(),
        })
        .await?;
    let incident = incident_repo
        .insert(repo::NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await?;
    let moderator_id = insert_moderator(pool).await?;
    let action = action_repo
        .insert(repo::NewAction {
            incident_id: incident.id,
            subject_id: subject.id,
            moderator_id,
            kind: ActionKind::Label,
            label: Some(polaris_types::LabelValue::new("spam")),
            reasoning: "Test reasoning for evidence-retry integration".to_owned(),
            policy_refs: vec![PolicyId::new("community-guidelines.spam.v1")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            llm_audit: None,
        })
        .await?;
    Ok(action.id.into_uuid())
}

async fn start_pg() -> Result<(sqlx::PgPool, impl Drop), Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    Ok((database.pool().clone(), container))
}

async fn fetch_job_row(
    pool: &sqlx::PgPool,
    action_id: uuid::Uuid,
) -> Result<JobRow, Box<dyn std::error::Error>> {
    let row = sqlx::query!(
        r#"
        SELECT status,
               attempt_count,
               last_attempt_at,
               next_attempt_at,
               last_error
        FROM evidence_jobs
        WHERE action_id = $1
        "#,
        action_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(JobRow {
        status: row.status,
        attempt_count: row.attempt_count,
        last_attempt_at: row.last_attempt_at,
        next_attempt_at: row.next_attempt_at,
        last_error: row.last_error,
    })
}

#[derive(Debug)]
struct JobRow {
    status: String,
    attempt_count: i32,
    last_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
}

/// Pull a failed row's `next_attempt_at` into the past so the next
/// worker tick reclaims it. The production worker's `mark_failed`
/// would set this naturally; we accelerate wall-clock here.
async fn make_due(
    pool: &sqlx::PgPool,
    action_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query!(
        r#"
        UPDATE evidence_jobs
        SET next_attempt_at = now() - interval '1 second'
        WHERE action_id = $1
        "#,
        action_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ── tests ───────────────────────────────────────────────────────────────

/// AC-1 (issue #69): a failed job transitions to `status='failed'`
/// with `attempt_count=1`, `last_attempt_at` populated, and
/// `next_attempt_at` strictly in the future. The very next worker
/// tick must *not* reclaim the row, because its schedule has not
/// elapsed yet.
#[tokio::test]
async fn failed_job_schedules_retry_in_the_future() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP evidence_retry schedule: docker daemon not reachable.");
        return Ok(());
    }
    let (pool, _container) = start_pg().await?;
    let action_id = seed_action_against_record(&pool).await?;

    let blob_store: Arc<dyn BlobStore> = Arc::new(InMemoryBlobStore::new());
    let fetcher = Arc::new(AlwaysFailFetcher);

    // Generous retry policy so we definitely don't roll over the
    // max-attempts ceiling on the first failure.
    let worker = EvidenceWorker::with_retry_policy(
        pool.clone(),
        blob_store.clone(),
        fetcher,
        4,
        Duration::from_millis(50),
        8,
        30,
    );

    let before = Utc::now();
    let processed = worker.run_once().await?;
    assert_eq!(processed, 1, "first tick must drain the pending row");

    let job = fetch_job_row(&pool, action_id).await?;
    assert_eq!(job.status, "failed");
    assert_eq!(job.attempt_count, 1);
    assert!(job.last_error.is_some(), "last_error must be set");
    let last_attempt_at = job
        .last_attempt_at
        .expect("last_attempt_at must be set on a failure");
    assert!(
        last_attempt_at >= before,
        "last_attempt_at must be >= the wall-clock right before the tick",
    );
    let next_attempt_at = job
        .next_attempt_at
        .expect("next_attempt_at must be set (failure is retry-eligible)");
    assert!(
        next_attempt_at > Utc::now(),
        "next_attempt_at must be strictly in the future ({next_attempt_at} > now)",
    );

    // A second tick fired immediately must NOT reclaim the row — the
    // schedule has not elapsed.
    let processed_again = worker.run_once().await?;
    assert_eq!(
        processed_again, 0,
        "second tick must skip the failed row whose next_attempt_at is still in the future",
    );

    Ok(())
}

/// AC-2 (issue #69): once `next_attempt_at` is past and the fetcher
/// recovers, the next tick reclaims the row, runs it, and transitions
/// to `status='done'` with `attempt_count=2`.
#[tokio::test]
async fn retry_succeeds_when_due_and_increments_attempt_count()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP evidence_retry succeed: docker daemon not reachable.");
        return Ok(());
    }
    let (pool, _container) = start_pg().await?;
    let action_id = seed_action_against_record(&pool).await?;

    let blob_store: Arc<dyn BlobStore> = Arc::new(InMemoryBlobStore::new());
    let fetcher = Arc::new(ToggleFetcher::new_failing());

    let worker = EvidenceWorker::with_retry_policy(
        pool.clone(),
        blob_store.clone(),
        fetcher.clone(),
        4,
        Duration::from_millis(50),
        8,
        30,
    );

    // First tick → failure.
    let processed = worker.run_once().await?;
    assert_eq!(processed, 1);
    let job = fetch_job_row(&pool, action_id).await?;
    assert_eq!(job.status, "failed");
    assert_eq!(job.attempt_count, 1);

    // Time-travel: pull next_attempt_at into the past.
    make_due(&pool, action_id).await?;

    // Flip the fetcher to succeed; next tick must reclaim and succeed.
    fetcher.set_succeed(true);
    let processed2 = worker.run_once().await?;
    assert_eq!(
        processed2, 1,
        "second tick must reclaim the now-due failed row"
    );

    let job_after = fetch_job_row(&pool, action_id).await?;
    assert_eq!(
        job_after.status, "done",
        "successful retry must end in done"
    );
    assert_eq!(
        job_after.attempt_count, 2,
        "attempt_count must be incremented on the retry attempt",
    );

    Ok(())
}

/// AC-3 (issue #69): exhausting `max_attempts` leaves the row
/// permanently failed (`status='failed'`, `attempt_count =
/// max_attempts`, `next_attempt_at IS NULL`). A subsequent worker
/// tick must NOT reclaim the row.
#[tokio::test]
async fn max_attempts_leaves_row_permanently_failed() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP evidence_retry max-attempts: docker daemon not reachable.");
        return Ok(());
    }
    let (pool, _container) = start_pg().await?;
    let action_id = seed_action_against_record(&pool).await?;

    let blob_store: Arc<dyn BlobStore> = Arc::new(InMemoryBlobStore::new());
    let fetcher: Arc<AlwaysFailFetcher> = Arc::new(AlwaysFailFetcher);

    let max_attempts: u32 = 3;
    let worker = EvidenceWorker::with_retry_policy(
        pool.clone(),
        blob_store.clone(),
        fetcher,
        4,
        Duration::from_millis(50),
        max_attempts,
        30,
    );

    // Loop max_attempts times. After tick N, attempt_count = N. On
    // the last tick (N == max_attempts) the worker must set
    // next_attempt_at = NULL (permanent failure).
    for n in 1..=max_attempts {
        // Force the row to be due for the next tick (no real wall
        // clock involved).
        if n > 1 {
            make_due(&pool, action_id).await?;
        }
        let processed = worker.run_once().await?;
        assert_eq!(processed, 1, "tick {n} must drain the row");
        let job = fetch_job_row(&pool, action_id).await?;
        assert_eq!(job.status, "failed", "tick {n}: status must be failed");
        assert_eq!(
            i32::try_from(n).unwrap_or(i32::MAX),
            job.attempt_count,
            "tick {n}: attempt_count must be {n}",
        );
        if n < max_attempts {
            assert!(
                job.next_attempt_at.is_some(),
                "tick {n}: not yet at ceiling — next_attempt_at must be SET",
            );
        } else {
            assert!(
                job.next_attempt_at.is_none(),
                "tick {n}: ceiling reached — next_attempt_at must be NULL",
            );
        }
    }

    // One more tick: the permanent-fail row has next_attempt_at =
    // NULL so the worker's claim WHERE clause excludes it (the
    // `next_attempt_at IS NOT NULL AND next_attempt_at <= now()`
    // predicate fails the IS NOT NULL guard). We deliberately do NOT
    // call `make_due` here — that would mutate `next_attempt_at` from
    // NULL to a past time and defeat the permanence guarantee under
    // test.
    let processed_after = worker.run_once().await?;
    assert_eq!(
        processed_after, 0,
        "permanently-failed row must never be reclaimed (next_attempt_at = NULL)",
    );
    let job_final = fetch_job_row(&pool, action_id).await?;
    assert_eq!(job_final.status, "failed");
    assert_eq!(
        i32::try_from(max_attempts).unwrap_or(i32::MAX),
        job_final.attempt_count,
        "attempt_count must remain at max_attempts after a no-op tick",
    );
    assert!(job_final.next_attempt_at.is_none());

    Ok(())
}
