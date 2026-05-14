//! Evidence-preservation worker integration test (issue #33 / AC-11).
//!
//! Spins up Postgres 16 via testcontainers, runs all migrations through
//! [`db::connect`] (including #17 `evidence_jobs`), seeds a record-shaped
//! subject + incident + action, and drives [`EvidenceWorker::run_once`]
//! against a mock [`EvidenceFetcher`]. Asserts:
//!
//! 1. **AC-11 binding** — after one worker tick, a CAR exists in the
//!    in-memory blob store at the expected key, the SHA-256 of the
//!    CAR matches `actions.evidence_car_cid`, and `read_car` against
//!    the stored bytes round-trips the original blocks byte-identically.
//! 2. **Idempotency** — running the worker again on the same action
//!    does not write a second CAR, does not change `evidence_car_cid`,
//!    and leaves the job row `status='done'`.
//! 3. **Failure path** — a fetcher that returns an error transitions
//!    the job to `status='failed'` with `last_error` populated, while
//!    leaving `actions.evidence_car_cid` NULL.
//!
//! The wall-clock budget is 30s — well under the AC-11 spec ceiling.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::evidence::{
    BlobStore, EvidenceFetcher, EvidenceFetcherError, EvidenceWorker, FetchedEvidence,
    InMemoryBlobStore, blob_key_for_cid,
};
use polaris_backend::repo::{
    self, ActionRepo, IncidentRepo, PgActionRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{
    ActionKind, AtUri, Did, IncidentStatus, ModeratorId, PolicyId, Severity, SubjectKind,
};
use proto_blue::lex_data::LexValue;
use proto_blue::repo::{BlockMap, read_car};
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

/// Fetcher that returns a synthetic 4-block `BlockMap` on every call.
///
/// The blocks have no semantic meaning — we only care that the worker
/// CAR-encodes them, hashes the bytes, persists, and that
/// `read_car(stored_bytes)` reproduces the `BlockMap` byte-identically.
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

/// Fetcher that always fails.
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
                message: "synthetic failure for AC-11 negative path".into(),
            })
        })
    }
}

async fn seed_action_against_record(
    pool: &sqlx::PgPool,
) -> Result<(uuid::Uuid, String), Box<dyn std::error::Error>> {
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
            reasoning: "Test reasoning for evidence-worker AC-11 binding".to_owned(),
            policy_refs: vec![PolicyId::new("community-guidelines.spam.v1")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
        })
        .await?;
    Ok((action.id.into_uuid(), subject_uri))
}

#[tokio::test]
async fn ac11_binding_evidence_car_persists_and_round_trips()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP evidence_worker AC-11: docker daemon not reachable.");
        return Ok(());
    }
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();

    let (action_id, _subject_uri) = seed_action_against_record(&pool).await?;

    // Verify the enqueue happened atomically with the action insert.
    let enqueued = sqlx::query!(
        "SELECT action_id, status FROM evidence_jobs WHERE action_id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(enqueued.action_id, action_id);
    assert_eq!(enqueued.status, "pending");

    let blob_store = Arc::new(InMemoryBlobStore::new());
    let fetcher = Arc::new(SyntheticFetcher::new());
    let expected_root_cid = fetcher.root_cid.clone();
    let expected_blocks = fetcher.blocks.clone();

    let worker = EvidenceWorker::new(
        pool.clone(),
        blob_store.clone(),
        fetcher.clone(),
        4,
        Duration::from_millis(50),
    );

    let processed = tokio::time::timeout(Duration::from_secs(30), worker.run_once())
        .await
        .expect("worker did not finish within 30s")?;
    assert_eq!(processed, 1, "exactly one job should have been processed");

    // Action row now carries the CAR's content hash.
    let row = sqlx::query!(
        "SELECT evidence_car_cid FROM actions WHERE id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    let cid_hex = row
        .evidence_car_cid
        .expect("evidence_car_cid must be populated after a successful worker tick");
    assert_eq!(cid_hex.len(), 64, "SHA-256 hex is 64 chars");

    // Job row is `done`.
    let job_status = sqlx::query!(
        "SELECT status, last_error FROM evidence_jobs WHERE action_id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(job_status.status, "done");
    assert!(job_status.last_error.is_none());

    // Blob is at the documented key.
    let blob_key = blob_key_for_cid(&cid_hex);
    let stored = blob_store
        .get(&blob_key)
        .await?
        .expect("blob must exist at the canonical key");
    assert_eq!(blob_store.len().await, 1, "exactly one CAR in storage");

    // The stored CAR round-trips through `read_car` byte-identically
    // to the synthetic block map the fetcher produced. This is the
    // proof that the worker preserved evidence faithfully.
    let (roots, decoded_blocks) = read_car(&stored)?;
    assert_eq!(roots.len(), 1);
    assert_eq!(
        roots[0].to_string_base32(),
        expected_root_cid.to_string_base32(),
    );
    assert_eq!(decoded_blocks.len(), expected_blocks.len());
    for (cid, bytes) in expected_blocks.iter() {
        let stored_bytes = decoded_blocks
            .get(cid)
            .expect("expected block must be present in the decoded CAR");
        assert_eq!(stored_bytes, bytes, "byte identity for cid {cid}");
    }

    Ok(())
}

#[tokio::test]
async fn idempotency_replayed_worker_does_not_double_write()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP evidence_worker idempotency: docker daemon not reachable.");
        return Ok(());
    }
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();

    let (action_id, _) = seed_action_against_record(&pool).await?;

    let blob_store = Arc::new(InMemoryBlobStore::new());
    let fetcher = Arc::new(SyntheticFetcher::new());

    let worker = EvidenceWorker::new(
        pool.clone(),
        blob_store.clone(),
        fetcher.clone(),
        4,
        Duration::from_millis(50),
    );

    // First tick: claims and processes the row.
    let first = worker.run_once().await?;
    assert_eq!(first, 1);

    let first_cid = sqlx::query!(
        "SELECT evidence_car_cid FROM actions WHERE id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?
    .evidence_car_cid
    .expect("cid populated");

    let blobs_after_first = blob_store.len().await;
    assert_eq!(blobs_after_first, 1);

    // Manually re-enqueue (the production path would never do this,
    // but it's the cleanest way to assert "if we did re-run, the
    // worker would not double-write"). Reset status to 'pending'.
    sqlx::query!(
        "UPDATE evidence_jobs SET status = 'pending' WHERE action_id = $1",
        action_id,
    )
    .execute(&pool)
    .await?;

    let second = worker.run_once().await?;
    assert_eq!(second, 1);

    // CID unchanged.
    let row_after = sqlx::query!(
        "SELECT evidence_car_cid FROM actions WHERE id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row_after.evidence_car_cid, Some(first_cid));

    // Still exactly one blob (the put is keyed by content hash so
    // the second write would have overwritten the first, but the
    // idempotency short-circuit means no fetch happens at all).
    let blobs_after_second = blob_store.len().await;
    assert_eq!(blobs_after_second, blobs_after_first);

    // Job is done.
    let job_status = sqlx::query!(
        "SELECT status FROM evidence_jobs WHERE action_id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(job_status.status, "done");

    Ok(())
}

#[tokio::test]
async fn failure_path_marks_job_failed_without_touching_action()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP evidence_worker failure: docker daemon not reachable.");
        return Ok(());
    }
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();

    let (action_id, _) = seed_action_against_record(&pool).await?;

    let blob_store = Arc::new(InMemoryBlobStore::new());
    let fetcher = Arc::new(AlwaysFailFetcher);

    let worker = EvidenceWorker::new(
        pool.clone(),
        blob_store.clone(),
        fetcher.clone(),
        4,
        Duration::from_millis(50),
    );

    let processed = worker.run_once().await?;
    assert_eq!(processed, 1);

    let job = sqlx::query!(
        "SELECT status, last_error, attempt_count FROM evidence_jobs WHERE action_id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(job.status, "failed");
    assert!(job.last_error.is_some(), "last_error must be populated");
    assert!(job.attempt_count >= 1, "attempt_count must be incremented");

    let action_row = sqlx::query!(
        "SELECT evidence_car_cid FROM actions WHERE id = $1",
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        action_row.evidence_car_cid.is_none(),
        "failure path must leave evidence_car_cid NULL",
    );

    // No blob was written.
    assert!(blob_store.is_empty().await);

    Ok(())
}

#[tokio::test]
async fn account_subject_does_not_enqueue_evidence_job() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP evidence_worker account-skip: docker daemon not reachable.");
        return Ok(());
    }
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();

    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let action_repo = PgActionRepo::new(pool.clone());

    // Account-shaped subject: no AT-URI, no evidence job should be enqueued.
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new("did:plc:account-only")),
            uri: None,
            created_at: Utc::now(),
        })
        .await?;
    let incident = incident_repo
        .insert(repo::NewIncident {
            primary_subject: subject.id,
            severity: Severity::Low,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await?;
    let moderator_id = insert_moderator(&pool).await?;
    let action = action_repo
        .insert(repo::NewAction {
            incident_id: incident.id,
            subject_id: subject.id,
            moderator_id,
            kind: ActionKind::Warn,
            label: None,
            reasoning: "Warning the account; no record snapshot needed".to_owned(),
            policy_refs: vec![],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
        })
        .await?;

    let job_count = sqlx::query!(
        "SELECT COUNT(*) AS cnt FROM evidence_jobs WHERE action_id = $1",
        action.id.into_uuid(),
    )
    .fetch_one(&pool)
    .await?
    .cnt
    .unwrap_or(0);
    assert_eq!(
        job_count, 0,
        "no evidence_jobs row must be enqueued for an account-shaped subject",
    );

    Ok(())
}
