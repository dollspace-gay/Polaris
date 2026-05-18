//! Faceted-filter integration tests for `GET /api/dashboard`
//! (issue #94 / mod-workstation feature #4).
//!
//! Hermetic per test: each test boots a fresh testcontainers Postgres
//! 16-alpine, applies all migrations via `db::connect`, seeds a small
//! fixture of three incidents with distinct reporter / category /
//! status / `opened_at`, builds the full router, and drives the
//! `/api/dashboard` route with the facet query parameters.
//!
//! The test suite pins the AC-1 expectation list verbatim:
//!
//! - No params → all open + escalated (default, AC-6 backward-compat)
//! - `?status=resolved` *(actually `?status=actioned`)* → narrowed
//! - `?category=spam` → narrowed
//! - `?reporter_did=did:plc:reporter_a` → narrowed
//! - malformed `?since=not-a-date` → 400
//! - inverted `?since=<future>&until=<past>` → 400
//! - all four facets composed → exactly the intersecting incident
//!
//! # Note on status taxonomy
//!
//! The spec calls out `?status=resolved`, but Polaris's incident
//! status enum uses `actioned` / `closed` for the resolved tier (see
//! migration `00000000000003_subjects_incidents.sql`). The test
//! filters on `actioned` to exercise the same "filter to a single
//! non-default status" code path the spec intended.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::middleware::auth::SESSION_COOKIE;
use polaris_backend::repo::{
    self, IncidentRepo, PgIncidentRepo, PgReportRepo, PgSubjectRepo, ReportRepo, SubjectRepo,
};
use polaris_types::{
    Did, IncidentId, IncidentStatus, ModeratorId, ReportCategory, Severity, SubjectKind,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors the rest of the
/// integration-test suite so the skip behaviour is uniform.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the (`db`, pool)
/// pair. The container handle is leaked so its `Drop` runs at process
/// exit — same pattern as `case_api.rs` / `appeals_workflow.rs`.
async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
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

/// Insert one moderator row + grant the Moderator role; mint a session
/// cookie for it. Returns the cookie the test passes through the
/// `Cookie` header.
async fn provision_moderator(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<String, Box<dyn std::error::Error>> {
    let external_id = format!("dashboard-filters-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    let moderator_id = ModeratorId(row.id);
    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id.0)
    .bind(Role::Moderator.as_db_str())
    .execute(pool)
    .await?;
    let session = sessions
        .create(AuthModeratorId(moderator_id.0), b"test-refresh-token")
        .await?;
    Ok(session.token.as_str().to_owned())
}

/// One incident's seed parameters.
struct SeedIncident {
    status: IncidentStatus,
    reporter_did: &'static str,
    category: &'static str,
    /// Offset (hours) added to `now` for `opened_at` — negative is
    /// "earlier".
    opened_offset_hours: i64,
}

struct SeededIncident {
    id: IncidentId,
}

/// Seed an incident with one report under it. Used by every test —
/// drives both the cluster-row's `status` / `opened_at` and the
/// joined report's `reporter_did` / `category` so the facet predicate
/// has something to discriminate on.
async fn seed_incident(
    pool: &PgPool,
    seed: SeedIncident,
) -> Result<SeededIncident, Box<dyn std::error::Error>> {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let report_repo = PgReportRepo::new(pool.clone());

    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new(format!(
                "did:plc:subj-{}",
                Uuid::new_v4().simple()
            ))),
            uri: None,
            created_at: Utc::now(),
        })
        .await?;

    let incident = incident_repo
        .insert(repo::NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: seed.status,
            assigned_to: None,
        })
        .await?;

    // The seeded `opened_at` is shifted to a non-default value so the
    // `since` / `until` range filter has something to bracket.
    let opened_at = Utc::now() + Duration::hours(seed.opened_offset_hours);
    sqlx::query("UPDATE incidents SET opened_at = $1 WHERE id = $2")
        .bind(opened_at)
        .bind(incident.id.0)
        .execute(pool)
        .await?;

    report_repo
        .insert(repo::NewReport {
            subject_id: subject.id,
            incident_id: Some(incident.id),
            reporter_did: Did::new(seed.reporter_did),
            category: ReportCategory::new(seed.category),
            body: "seed report body".to_owned(),
        })
        .await?;

    Ok(SeededIncident { id: incident.id })
}

/// Assemble the (`router`, `pool`, `cookie`) fixture used by every test.
///
/// The three seeded incidents are:
///
/// 1. `(Open, reporter_a, spam, -1h)`
/// 2. `(Escalated, reporter_b, harassment, -12h)`
/// 3. `(Actioned, reporter_a, spam, -48h)`  ← resolved tier
///
/// They cover every facet axis: status (open/escalated vs. actioned),
/// reporter (`reporter_a` shared by 1 & 3), category (spam shared by
/// 1 & 3, harassment only on 2), and `opened_at` (recent vs. > 24h old).
struct Fixture {
    router: Router,
    cookie: String,
    incident_open: IncidentId,
    incident_escalated: IncidentId,
    incident_actioned: IncidentId,
}

async fn boot_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let (db, pool) = boot_db().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(db, state);

    let cookie = provision_moderator(&pool, &sessions).await?;

    let open = seed_incident(
        &pool,
        SeedIncident {
            status: IncidentStatus::Open,
            reporter_did: "did:plc:reporter_a",
            category: "spam",
            opened_offset_hours: -1,
        },
    )
    .await?;
    let escalated = seed_incident(
        &pool,
        SeedIncident {
            status: IncidentStatus::Escalated,
            reporter_did: "did:plc:reporter_b",
            category: "harassment",
            opened_offset_hours: -12,
        },
    )
    .await?;
    let actioned = seed_incident(
        &pool,
        SeedIncident {
            status: IncidentStatus::Actioned,
            reporter_did: "did:plc:reporter_a",
            category: "spam",
            opened_offset_hours: -48,
        },
    )
    .await?;

    Ok(Fixture {
        router,
        cookie,
        incident_open: open.id,
        incident_escalated: escalated.id,
        incident_actioned: actioned.id,
    })
}

/// Issue a `GET /api/dashboard?<query>` request with the seeded
/// session cookie attached. Returns the parsed JSON body.
async fn fetch_dashboard(
    router: &Router,
    cookie: &str,
    query: &str,
) -> Result<(StatusCode, serde_json::Value), Box<dyn std::error::Error>> {
    let uri = if query.is_empty() {
        "/api/dashboard".to_owned()
    } else {
        format!("/api/dashboard?{query}")
    };
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let body: serde_json::Value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok((status, body))
}

/// Read the cluster ids out of a dashboard snapshot JSON value.
/// Returns them in `BTreeSet`-style sorted order so the equality
/// assertions don't depend on the SQL `ORDER BY` ordering (the
/// cluster sort is by `severity × reach`, which is identical for the
/// three seeded rows).
fn cluster_ids(body: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = body["clusters"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c["incident_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

fn id_to_string(id: IncidentId) -> String {
    id.0.to_string()
}

// ── 1. Default (no params) returns the open + escalated set ─────────

#[tokio::test]
async fn dashboard_with_no_params_returns_default_set() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP dashboard_filters::dashboard_with_no_params_returns_default_set");
        return Ok(());
    }
    let fix = boot_fixture().await?;
    let (status, body) = fetch_dashboard(&fix.router, &fix.cookie, "").await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "default request must 200; body {body}"
    );
    let ids = cluster_ids(&body);
    // Open + Escalated → 2 incidents; the actioned one stays hidden.
    let mut expected = vec![
        id_to_string(fix.incident_open),
        id_to_string(fix.incident_escalated),
    ];
    expected.sort();
    assert_eq!(
        ids, expected,
        "default body returned wrong clusters: {body}"
    );
    Ok(())
}

// ── 2. ?status=actioned returns only the resolved-tier incident ─────

#[tokio::test]
async fn dashboard_with_status_filter_narrows_set() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP dashboard_filters::dashboard_with_status_filter_narrows_set");
        return Ok(());
    }
    let fix = boot_fixture().await?;
    let (status, body) = fetch_dashboard(&fix.router, &fix.cookie, "status=actioned").await?;
    assert_eq!(status, StatusCode::OK);
    let ids = cluster_ids(&body);
    assert_eq!(
        ids,
        vec![id_to_string(fix.incident_actioned)],
        "status=actioned must return only the actioned incident: {body}"
    );
    Ok(())
}

// ── 3. ?category=harassment returns only the harassment incident ────

#[tokio::test]
async fn dashboard_with_category_filter_narrows_set() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP dashboard_filters::dashboard_with_category_filter_narrows_set");
        return Ok(());
    }
    let fix = boot_fixture().await?;
    let (status, body) = fetch_dashboard(&fix.router, &fix.cookie, "category=harassment").await?;
    assert_eq!(status, StatusCode::OK);
    let ids = cluster_ids(&body);
    assert_eq!(
        ids,
        vec![id_to_string(fix.incident_escalated)],
        "category=harassment must return only the harassment cluster: {body}"
    );
    Ok(())
}

// ── 4. ?reporter_did=did:plc:reporter_b returns only B's incident ───

#[tokio::test]
async fn dashboard_with_reporter_did_filter_narrows_set() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!("SKIP dashboard_filters::dashboard_with_reporter_did_filter_narrows_set");
        return Ok(());
    }
    let fix = boot_fixture().await?;
    let (status, body) = fetch_dashboard(
        &fix.router,
        &fix.cookie,
        "reporter_did=did%3Aplc%3Areporter_b",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let ids = cluster_ids(&body);
    assert_eq!(
        ids,
        vec![id_to_string(fix.incident_escalated)],
        "reporter_did=did:plc:reporter_b must return only reporter B's cluster: {body}"
    );
    Ok(())
}

// ── 5. Inverted since/until returns 400 ─────────────────────────────

#[tokio::test]
async fn dashboard_with_inverted_range_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP dashboard_filters::dashboard_with_inverted_range_returns_400");
        return Ok(());
    }
    let fix = boot_fixture().await?;
    let since = (Utc::now() + Duration::hours(48)).to_rfc3339();
    let until = (Utc::now() - Duration::hours(48)).to_rfc3339();
    let query = format!(
        "since={}&until={}",
        urlencoding_min(&since),
        urlencoding_min(&until),
    );
    let (status, body) = fetch_dashboard(&fix.router, &fix.cookie, &query).await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "inverted range must 400; body {body}"
    );
    assert_eq!(body["code"], "bad_request", "body {body}");
    Ok(())
}

// ── 6. Malformed since=not-a-date returns 400 ───────────────────────

#[tokio::test]
async fn dashboard_with_malformed_since_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP dashboard_filters::dashboard_with_malformed_since_returns_400");
        return Ok(());
    }
    let fix = boot_fixture().await?;
    let (status, body) = fetch_dashboard(&fix.router, &fix.cookie, "since=not-a-date").await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "malformed since must 400; body {body}"
    );
    assert_eq!(body["code"], "bad_request", "body {body}");
    Ok(())
}

// ── 7. All four facets composed return the single intersection ──────

#[tokio::test]
async fn dashboard_with_all_facets_composed_returns_single_incident()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP dashboard_filters::dashboard_with_all_facets_composed_returns_single_incident"
        );
        return Ok(());
    }
    let fix = boot_fixture().await?;
    // Pick the open-incident bucket and assert exactly one cluster
    // comes back: open + spam + reporter_a + window straddling -1h.
    let since = (Utc::now() - Duration::hours(6)).to_rfc3339();
    let until = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let query = format!(
        "status=open&category=spam&reporter_did={}&since={}&until={}",
        urlencoding_min("did:plc:reporter_a"),
        urlencoding_min(&since),
        urlencoding_min(&until),
    );
    let (status, body) = fetch_dashboard(&fix.router, &fix.cookie, &query).await?;
    assert_eq!(status, StatusCode::OK, "body {body}");
    let ids = cluster_ids(&body);
    assert_eq!(
        ids,
        vec![id_to_string(fix.incident_open)],
        "composed facets must return the open incident only: {body}"
    );
    Ok(())
}

/// Tiny URL-encoder for the few characters this test needs to
/// percent-encode (`:` and `+` in DIDs/RFC3339 stamps). Kept local to
/// avoid pulling in the `url` crate as a dev-dep just for two tests.
fn urlencoding_min(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}
