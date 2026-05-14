//! Database layer: Postgres connection pool, migrations, and healthcheck
//! primitive.
//!
//! # Design invariants
//!
//! - **No string-built SQL.** Once business queries arrive in #13 they will go
//!   through `sqlx::query!` / `sqlx::query_as!` macros so the SQL is verified
//!   against the live schema at compile time. This module deliberately
//!   contains *zero* SQL today — [`Db::ping`] only acquires a connection.
//! - **`PgPool` is not wrapped in `Arc`.** `sqlx::PgPool` is already internally
//!   reference-counted; cloning it is cheap and shares the underlying pool.
//!   Wrapping it in `Arc<PgPool>` would double-count and obscure the
//!   ergonomics.
//! - **Connect = migrate.** [`connect`] runs `sqlx::migrate!()` on success.
//!   A successful `Db` therefore implies a schema at the embedded migration
//!   set. Boot is fail-closed: if migrations fail the binary refuses to serve.
//! - **All errors are typed.** No `anyhow` in this module — the public surface
//!   returns [`DbError`] so callers can match on variants. `anyhow` is
//!   reserved for the binary entrypoint.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

use crate::config::DbConfig;

/// Errors raised by the database layer.
///
/// Variants intentionally collapse different `sqlx::Error` cases into named
/// pool / migrate / acquire buckets so the public API does not leak the
/// `sqlx::Error` enum into downstream match arms. Inner errors are preserved
/// via `#[source]` so the chain remains visible in logs.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// The pool failed to open against the configured URL.
    #[error("failed to connect to Postgres at the configured URL")]
    Connect(#[source] sqlx::Error),

    /// One or more migrations failed to apply.
    #[error("failed to apply embedded migrations")]
    Migrate(#[source] sqlx::migrate::MigrateError),

    /// `pool.acquire()` failed — the pool is up but has no healthy backend.
    #[error("failed to acquire a Postgres connection from the pool")]
    Acquire(#[source] sqlx::Error),
}

/// A connected, migrated database handle.
///
/// `Db` holds a `PgPool` directly — `PgPool` is internally `Arc`-shared, so
/// cloning a `Db` is cheap and propagates the same underlying pool. This is
/// the canonical handle to pass into Axum state (`State<Db>`) and into
/// repository structs as they arrive in M1+.
#[derive(Debug, Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Borrow the underlying `PgPool` for use by repository code.
    ///
    /// Repos take `&PgPool` so they cannot accidentally retain ownership of
    /// the pool independently of the [`Db`] that produced it.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Cheaply verify the pool can hand out a connection.
    ///
    /// This deliberately performs **no SQL**: it acquires a connection,
    /// observes that the pool is healthy, and drops the connection back into
    /// the pool. The first business query lands in #13; until then, the
    /// healthcheck contract is "the pool can talk to Postgres," not "the
    /// schema is correct."
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Acquire`] if the pool has no healthy backend
    /// (Postgres down, network partition, exhausted pool).
    pub async fn ping(&self) -> Result<(), DbError> {
        let conn = self.pool.acquire().await.map_err(DbError::Acquire)?;
        // Explicit drop documents the intent: we are proving the pool is
        // healthy, not running a query. Without the named binding clippy
        // would (correctly) flag a `let _ = …` as a smell.
        drop(conn);
        Ok(())
    }
}

/// Open a Postgres pool against `cfg` and apply embedded migrations.
///
/// On success, the returned [`Db`] is connected to a Postgres at
/// `cfg.url` with all migrations in `polaris-backend/migrations/` applied.
///
/// # Errors
///
/// - [`DbError::Connect`] if the pool cannot open (bad URL, auth failure,
///   Postgres unreachable within the acquire timeout).
/// - [`DbError::Migrate`] if a migration fails or the recorded checksum of
///   an already-applied migration disagrees with the file on disk
///   (sqlx will refuse to proceed in that case — by design).
pub async fn connect(cfg: &DbConfig) -> Result<Db, DbError> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(Duration::from_secs(cfg.acquire_timeout_secs))
        .connect(&cfg.url)
        .await
        .map_err(DbError::Connect)?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(DbError::Migrate)?;

    Ok(Db { pool })
}
