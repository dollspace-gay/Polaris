//! Shared fixtures for the threat-model test suite (issue #39).
//!
//! Each threat test owns its own Postgres container so the suite is
//! hermetic per test (forbidden-pattern §3 of the architect's
//! pre-flight). This module provides the common boot-strap that avoids
//! 6× boilerplate.
//!
//! # Skip behaviour
//!
//! All threat tests follow the project-wide convention from
//! `tests/audit_chain.rs`: if the Docker daemon is not reachable the
//! test prints a clear `SKIP` line and returns `Ok(())`. The
//! `#[tokio::test]` machinery requires `Result`-returning bodies, so
//! the helper is structured as `boot_or_skip() -> Option<ThreatFixture>`
//! and each test short-circuits on `None`.
//!
//! # Why this is a subdirectory module, not a top-level `tests/<x>.rs`
//!
//! Cargo's integration-test discovery only registers `tests/*.rs` files
//! as separate binaries; subdirectories are left alone. Placing the
//! shared helpers under `tests/threats_common/mod.rs` and referencing
//! them with `mod threats_common;` from each `threat_*.rs` test is the
//! canonical pattern (cargo book §3.4 "integration tests").

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration-test helper module — each test pulls a subset of \
              this module; the unused-warnings are expected. Test code may \
              panic per rust-quality §7."
)]

use std::process::Command;

use chrono::Utc;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::{
    IncidentRepo as _, NewIncident, NewSubject, PgIncidentRepo, PgSubjectRepo, SubjectRepo as _,
};
use polaris_types::{
    Did, IncidentId, IncidentStatus, ModeratorId, Severity, SubjectId, SubjectKind,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner as _;
use uuid::Uuid;

/// Returns true when the Docker daemon is reachable, false otherwise.
///
/// Mirrors the convention used across `tests/audit_chain.rs`,
/// `tests/label_emitter.rs`, `tests/repo_roundtrip.rs`, etc. Tests
/// short-circuit on `false` with a printed `SKIP` line.
pub fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A freshly-booted Postgres 16-alpine container, fully migrated, plus
/// the pool that talks to it. The container handle is held inside the
/// struct so the container only stops when [`ThreatFixture`] is
/// dropped — the pool would otherwise outlive the database it points
/// at and tests would race.
pub struct ThreatFixture {
    /// Connection pool against the freshly-migrated database.
    pub pool: PgPool,
    /// Holds the container alive for the lifetime of the test. Never
    /// inspected directly — the `_` prefix marks it as a lifetime
    /// anchor only.
    pub _container: ContainerAsync<Postgres>,
}

impl ThreatFixture {
    /// Boot a Postgres 16-alpine container, run every production
    /// migration through the standard `db::connect` path, and return
    /// the migrated pool.
    ///
    /// # Errors
    ///
    /// Surfaces container-start errors and migration errors via the
    /// returned `Box<dyn Error>`.
    pub async fn boot() -> Result<Self, Box<dyn std::error::Error>> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host_port = container.get_host_port_ipv4(5432).await?;
        let cfg = DbConfig {
            url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
            max_connections: 4,
            min_connections: 1,
            acquire_timeout_secs: 10,
        };
        let database = db::connect(&cfg).await?;
        Ok(Self {
            pool: database.pool().clone(),
            _container: container,
        })
    }

    /// Insert a moderator row directly via SQL and return the
    /// generated id. The auth repo isn't part of the threat-test
    /// surface; the helper just satisfies the FK on `actions`.
    ///
    /// # Errors
    ///
    /// Propagates any underlying sqlx error.
    pub async fn insert_moderator(&self) -> Result<ModeratorId, sqlx::Error> {
        let external_id = format!("threat-test-{}", Uuid::new_v4());
        let row = sqlx::query!(
            r"INSERT INTO moderators (external_id, auth_backend)
              VALUES ($1, 'oidc')
              RETURNING id",
            external_id,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(ModeratorId(row.id))
    }

    /// Insert an `Account`-kind [`polaris_types::Subject`] keyed on a
    /// freshly-minted DID. Returns the assigned subject id.
    ///
    /// # Errors
    ///
    /// Propagates any underlying repo error.
    pub async fn insert_account_subject(
        &self,
        did_str: &str,
    ) -> Result<SubjectId, Box<dyn std::error::Error>> {
        let repo = PgSubjectRepo::new(self.pool.clone());
        let subject = repo
            .insert(NewSubject {
                kind: SubjectKind::Account,
                did: Some(Did::new(did_str)),
                uri: None,
                created_at: Utc::now(),
            })
            .await?;
        Ok(subject.id)
    }

    /// Insert a fresh open incident against `subject_id`. Returns the
    /// assigned incident id.
    ///
    /// # Errors
    ///
    /// Propagates any underlying repo error.
    pub async fn insert_incident(
        &self,
        subject_id: SubjectId,
        severity: Severity,
    ) -> Result<IncidentId, Box<dyn std::error::Error>> {
        let repo = PgIncidentRepo::new(self.pool.clone());
        let incident = repo
            .insert(NewIncident {
                primary_subject: subject_id,
                severity,
                status: IncidentStatus::Open,
                assigned_to: None,
            })
            .await?;
        Ok(incident.id)
    }
}
