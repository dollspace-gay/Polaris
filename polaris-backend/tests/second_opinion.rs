//! Second-opinion thread end-to-end integration test (issue #25).
//!
//! Spins up Postgres 16 via testcontainers, applies every migration
//! through `db::connect`, then exercises the four protocol-bearing
//! rules from `design.md` §5.6 + the architect's #25 pre-flight against
//! the live repo / API handlers:
//!
//! 1. **Open + append + read in order.** Open a thread, append a
//!    series of messages, then `get_thread_with_messages` returns them
//!    in chronological order with the right authorship.
//! 2. **Full-text search hits the GIN index.** Append messages with
//!    distinct text; search for a specific token returns the expected
//!    matches with non-zero `ts_rank_cd`.
//! 3. **Parameterised tsquery safety.** A search for input containing
//!    `'; DROP TABLE…` style payloads returns empty (no error, no
//!    side effect, no rows). This proves the user input flows through
//!    `plainto_tsquery($1)` as literal text — no operator injection.
//! 4. **Append-only at the DB.** A raw `UPDATE` on
//!    `second_opinion_messages.body` raises SQLSTATE `P0001`; the row's
//!    body stays byte-identical to the original; the repo's
//!    `From<sqlx::Error>` impl routes the error to
//!    `RepoError::AppendOnlyViolation`.
//!
//! # Why drive repos + handlers, not the full Axum router
//!
//! Wiring the full Axum router would require minting a session cookie
//! and threading a cookie-shaped `Request<Body>` through `tower::Service`.
//! The behaviour under test is the second-opinion repo + handler +
//! search-projection triad; all three are reachable by calling the
//! handlers directly with the same extractor wrappers axum would
//! inject. The cookie middleware has its own integration coverage in
//! `tests/oidc_login_flow.rs`. This matches the choice already made by
//! `tests/appeals_workflow.rs`, `tests/reversal_workflow.rs`, and
//! `tests/pattern_actions.rs`.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message and
//! returns successfully — same pattern as the other repo-flavoured
//! integration tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::Utc;
use polaris_backend::api::error::ApiError;
use polaris_backend::api::second_opinion::{
    AppendMessageBody, OpenThreadBody, SearchQuery, append_message, get_thread, open_thread,
    search_threads,
};
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorAuthCtx, ModeratorId as AuthModeratorId};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::{
    self, IncidentRepo, PgIncidentRepo, PgSecondOpinionRepo, PgSubjectRepo, RepoError,
    SecondOpinionRepo, SubjectRepo, ThreadId,
};
use polaris_types::{Did, IncidentStatus, ModeratorId, Severity, SubjectKind};
use sqlx::PgPool;
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

async fn insert_moderator(pool: &PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("second-opinion-test-{}", Uuid::new_v4());
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

fn ctx_for(moderator_id: ModeratorId) -> ModeratorAuthCtx {
    ModeratorAuthCtx::new(
        AuthModeratorId(moderator_id.0),
        std::collections::HashSet::new(),
    )
}

async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
    // Postgres 16-alpine is the architect's #25 pre-flight target. The
    // `body_tsv tsvector GENERATED ALWAYS AS … STORED` column added in
    // migration 11 requires Postgres ≥ 12; the testcontainers-modules
    // default tag `11-alpine` is too old and rejects the migration with
    // SQLSTATE 42601. Pinning the tag here keeps this test free of an
    // implicit dependency on the upstream default.
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();
    std::mem::forget(container);
    Ok((db, pool))
}

fn fresh_api_state(pool: PgPool) -> ApiState {
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    ApiState::new(pool, sessions)
}

#[tokio::test]
async fn second_opinion_workflow_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP second_opinion_workflow: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test.",
        );
        return Ok(());
    }

    let (_db, pool) = boot_db().await?;
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let so_repo = PgSecondOpinionRepo::new(pool.clone());

    // Seed an incident the thread can attach to.
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new("did:plc:second-opinion-target")),
            uri: None,
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

    let junior = insert_moderator(&pool).await?;
    let senior = insert_moderator(&pool).await?;

    // ── Test 1: open thread + append messages → read in order ────────
    // The thread carries no draft action; this is the abstract-thread
    // path the §5.6 design explicitly accommodates.
    let state = fresh_api_state(pool.clone());
    let (status, Json(opened)) = open_thread(
        State(state.clone()),
        Extension(ctx_for(junior)),
        Path(incident.id),
        Json(OpenThreadBody {
            draft_action_id: None,
            initial_message: "I want a second opinion on this borderline harassment case."
                .to_owned(),
        }),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    let thread_id = opened.thread_id;
    let initial_message_id = opened.initial_message_id;

    // Append a senior reply and a follow-up from the junior.
    let (_status, Json(reply1)) = append_message(
        State(state.clone()),
        Extension(ctx_for(senior)),
        Path(thread_id),
        Json(AppendMessageBody {
            body: "Looks like coordinated brigading to me; check the network context.".to_owned(),
            replaces: None,
        }),
    )
    .await?;
    let (_status, Json(reply2)) = append_message(
        State(state.clone()),
        Extension(ctx_for(junior)),
        Path(thread_id),
        Json(AppendMessageBody {
            body: "Agreed, applying the brigading label per policy.".to_owned(),
            replaces: None,
        }),
    )
    .await?;

    // Direct-repo read — proves the chronological-order contract.
    let (thread, messages) = so_repo
        .get_thread_with_messages(thread_id)
        .await?
        .expect("thread must exist after open");
    assert_eq!(thread.id, thread_id);
    assert_eq!(thread.incident_id, incident.id);
    assert_eq!(thread.requested_by, junior);
    assert!(thread.draft_action_id.is_none());
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].id, initial_message_id);
    assert_eq!(messages[1].id, reply1.message_id);
    assert_eq!(messages[2].id, reply2.message_id);
    assert_eq!(messages[0].moderator_id, junior);
    assert_eq!(messages[1].moderator_id, senior);
    assert_eq!(messages[2].moderator_id, junior);
    // Chronological invariant: each row's created_at is monotonically
    // non-decreasing.
    assert!(messages[0].created_at <= messages[1].created_at);
    assert!(messages[1].created_at <= messages[2].created_at);

    // Edit-via-new-row: amend reply1 by appending a *new* row whose
    // `replaces_message_id` points at reply1. The original row stays
    // put — the audit chain is total.
    let (_status, Json(amended)) = append_message(
        State(state.clone()),
        Extension(ctx_for(senior)),
        Path(thread_id),
        Json(AppendMessageBody {
            body: "Correction: brigading + sock-puppet ring. Tag both.".to_owned(),
            replaces: Some(reply1.message_id),
        }),
    )
    .await?;
    let (_thread, messages_after_edit) = so_repo
        .get_thread_with_messages(thread_id)
        .await?
        .expect("thread present after edit");
    assert_eq!(
        messages_after_edit.len(),
        4,
        "the amendment writes a new row; the original survives"
    );
    let amend_row = messages_after_edit
        .iter()
        .find(|m| m.id == amended.message_id)
        .expect("amendment row present");
    assert_eq!(amend_row.replaces_message_id, Some(reply1.message_id));

    // GET /api/threads/:thread_id round-trip.
    let Json(view) = get_thread(
        State(state.clone()),
        Extension(ctx_for(senior)),
        Path(thread_id),
    )
    .await?;
    assert_eq!(view.thread.id, thread_id);
    assert_eq!(view.messages.len(), 4);

    // ── Test 2: full-text search finds the rare token ────────────────
    // Append a message with a distinctive lexeme that does not appear
    // elsewhere; search must return *exactly* the rows that contain it,
    // with non-zero rank.
    let (_status, Json(rare_msg)) = append_message(
        State(state.clone()),
        Extension(ctx_for(senior)),
        Path(thread_id),
        Json(AppendMessageBody {
            body: "Document this snowflake-pattern verdict for future reference.".to_owned(),
            replaces: None,
        }),
    )
    .await?;

    let Json(rare_hits) = search_threads(
        State(state.clone()),
        Extension(ctx_for(junior)),
        Query(SearchQuery {
            q: "snowflake".to_owned(),
            limit: None,
        }),
    )
    .await?;
    assert!(
        !rare_hits.hits.is_empty(),
        "rare-token search must return at least one hit"
    );
    let snowflake_hit = rare_hits
        .hits
        .iter()
        .find(|h| h.message.id == rare_msg.message_id)
        .expect("the message containing 'snowflake' must appear in the hits");
    assert!(
        snowflake_hit.rank > 0.0,
        "ts_rank_cd must be positive for a matched row; got {}",
        snowflake_hit.rank,
    );
    // And the un-matched messages must not appear in the hit set.
    for hit in &rare_hits.hits {
        assert!(
            hit.message.body.to_lowercase().contains("snowflake"),
            "hit body must contain the search token; body was: {:?}",
            hit.message.body,
        );
    }

    // Search for a common stem ("brigading") returns multiple hits
    // including the original brigading messages from earlier scenarios.
    let Json(common_hits) = search_threads(
        State(state.clone()),
        Extension(ctx_for(junior)),
        Query(SearchQuery {
            q: "brigading".to_owned(),
            limit: None,
        }),
    )
    .await?;
    assert!(
        common_hits.hits.len() >= 2,
        "common-stem search must return ≥ 2 hits; got {}",
        common_hits.hits.len(),
    );

    // ── Test 3: parameterised tsquery — injection payload is safe ───
    // The payload contains tsquery operators (`&`, `|`, `!`, `<->`)
    // and a classic SQL-injection prefix. `plainto_tsquery` treats the
    // whole string as natural-language input; the literal tokens
    // `DROP`, `TABLE`, `users`, `--` won't match any of our messages
    // (no message body contains those words), so the hit set must be
    // empty. Critically, the call must NOT error and the DB must still
    // be intact (proven by a follow-up query that succeeds).
    let payload = "'; DROP TABLE second_opinion_messages; -- !brigading & spam | sock-puppet";
    let Json(injection_hits) = search_threads(
        State(state.clone()),
        Extension(ctx_for(junior)),
        Query(SearchQuery {
            q: payload.to_owned(),
            limit: None,
        }),
    )
    .await?;
    assert!(
        injection_hits.hits.is_empty(),
        "injection payload must not match any real message; got hits: {:?}",
        injection_hits
            .hits
            .iter()
            .map(|h| &h.message.body)
            .collect::<Vec<_>>(),
    );
    // The table is still present — a fresh `search` for the rare token
    // returns the same row it did before.
    let Json(re_check) = search_threads(
        State(state.clone()),
        Extension(ctx_for(junior)),
        Query(SearchQuery {
            q: "snowflake".to_owned(),
            limit: None,
        }),
    )
    .await?;
    assert!(
        !re_check.hits.is_empty(),
        "the table must still be intact after the attempted-injection search",
    );

    // ── Test 4: append-only — raw UPDATE is rejected by the trigger ──
    // Pick any message id from the thread; attempt an UPDATE that
    // bypasses the repo. The trigger must raise SQLSTATE P0001 and the
    // body must stay byte-identical.
    let target_id = initial_message_id;
    let original_body = messages_after_edit
        .iter()
        .find(|m| m.id == target_id)
        .map(|m| m.body.clone())
        .expect("initial message present");

    let raw_result = sqlx::query("UPDATE second_opinion_messages SET body = $1 WHERE id = $2")
        .bind("MUTATED — must never persist.")
        .bind(target_id.into_uuid())
        .execute(&pool)
        .await;
    let err = raw_result.expect_err("UPDATE on second_opinion_messages must be rejected");
    match &err {
        sqlx::Error::Database(db_err) => {
            let code = db_err
                .code()
                .map(std::borrow::Cow::into_owned)
                .expect("rejected UPDATE must carry a SQLSTATE");
            assert_eq!(
                code, "P0001",
                "expected P0001 (PL/pgSQL RAISE EXCEPTION), got {code} with message: {db_err}",
            );
            assert!(
                db_err.message().to_lowercase().contains("append-only"),
                "trigger message should mention append-only; got: {}",
                db_err.message(),
            );
        }
        other => panic!("expected sqlx::Error::Database, got: {other:?}"),
    }

    // The repo's `From<sqlx::Error>` impl routes SQLSTATE P0001 to
    // `RepoError::AppendOnlyViolation` — that's the contract repo
    // callers depend on.
    let routed: RepoError = err.into();
    assert!(
        matches!(routed, RepoError::AppendOnlyViolation(_)),
        "RepoError must classify SQLSTATE P0001 as AppendOnlyViolation, got: {routed:?}",
    );

    // The row's body is unchanged.
    let (_thread, messages_after_failed_update) = so_repo
        .get_thread_with_messages(thread_id)
        .await?
        .expect("thread present after failed update");
    let post_body = messages_after_failed_update
        .iter()
        .find(|m| m.id == target_id)
        .map(|m| m.body.clone())
        .expect("initial message still present");
    assert_eq!(
        post_body, original_body,
        "body must be byte-identical after the rejected UPDATE",
    );

    // Empty-body / over-cap rejection at the API layer. A `403`-style
    // input rejection happens before any DB round trip.
    let too_long = "a".repeat(16_385);
    let err = append_message(
        State(state.clone()),
        Extension(ctx_for(junior)),
        Path(thread_id),
        Json(AppendMessageBody {
            body: too_long,
            replaces: None,
        }),
    )
    .await
    .expect_err("over-cap body must be rejected at the API layer");
    assert!(
        matches!(err, ApiError::BadRequest(_)),
        "expected BadRequest, got {err:?}",
    );

    // Search for a non-existent thread id returns 404 via the
    // GET /api/threads/:thread_id handler.
    let phantom = ThreadId::new();
    let err = get_thread(State(state), Extension(ctx_for(junior)), Path(phantom))
        .await
        .expect_err("non-existent thread id must surface NotFound");
    assert!(
        matches!(err, ApiError::NotFound),
        "expected NotFound, got {err:?}"
    );

    Ok(())
}
