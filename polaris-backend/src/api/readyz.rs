//! `GET /readyz` — Kubernetes-style readiness probe (REQ-D1 / AC-D1).
//!
//! Distinct from [`crate::api::healthz`]:
//!
//! - `/healthz` answers "is the process alive and can it talk to the DB?".
//!   It is a liveness probe — a failing `/healthz` should trigger restart.
//! - `/readyz` answers "should this pod receive traffic right now?". It is
//!   a readiness probe — a failing `/readyz` keeps the pod out of the
//!   load-balancer rotation but does NOT trigger restart (the pod might
//!   still be useful for the setup-wizard surface while it's not ready
//!   for moderator traffic).
//!
//! # Body shape
//!
//! ```json
//! {
//!   "ready": true,
//!   "signing_key_provisioned": true,
//!   "last_emit_at": "2026-05-15T19:00:00Z",
//!   "db_reachable": true,
//!   "setup_complete": true
//! }
//! ```
//!
//! `ready` is true iff `signing_key_provisioned && db_reachable`.
//! `setup_complete` is informational — an operator may want readiness
//! traffic flowing while the wizard's PLC step is still pending so they
//! can hit `/setup`. The handler returns `200 OK` when `ready == true`
//! and `503 Service Unavailable` (same body) when `ready == false`.
//!
//! # State of derivation
//!
//! - `signing_key_provisioned` — read
//!   `ApiState::active_signer.borrow().clone().public_key_did()`; true
//!   iff the DID is non-empty. The `StubSigner` returns the empty
//!   string until the setup wizard runs, which is exactly the
//!   distinguisher REQ-A1 carved out.
//! - `db_reachable` — `SELECT 1::int` via `sqlx::query_scalar!`. Errors
//!   short-circuit to `db_reachable = false`.
//! - `last_emit_at` — `SELECT MAX(signed_at) FROM labels`. Null until
//!   the first label is emitted.
//! - `setup_complete` — `polaris_setup_state.did_document_updated_at
//!   IS NOT NULL`. Same heuristic
//!   [`crate::api::whoami`] uses for `first_run`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::state::ApiState;

/// JSON body for `GET /readyz`. Serialised once on every probe; cheap
/// because the field count is fixed and the strings are short.
///
/// The struct deliberately carries four boolean fields. Each one
/// signals a distinct operator-visible condition (`ready`,
/// `signing_key_provisioned`, `db_reachable`, `setup_complete`); a
/// two-variant enum would collapse independently-observable signals
/// into one and break the readiness body's wire contract, which
/// Kubernetes / Docker / Grafana scrape against by field name.
#[allow(
    clippy::struct_excessive_bools,
    reason = "REQ-D1 specifies four boolean fields by name; the wire shape is the contract"
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyzBody {
    /// True iff `signing_key_provisioned && db_reachable`. The
    /// orchestrator gates traffic on this field.
    pub ready: bool,
    /// True iff the active signer advertises a non-empty `did:key:z…`.
    /// The `StubSigner` returns "" until the wizard mints a real key
    /// (REQ-A1 / REQ-A4), so this is a precise distinguisher between
    /// "deferred provisioning" and "ready to emit".
    pub signing_key_provisioned: bool,
    /// RFC-3339 timestamp of the most recently emitted label, or
    /// `null` if no labels have ever been emitted. Operators use this
    /// to detect a wedged emitter (alert when this field stops
    /// advancing under load).
    pub last_emit_at: Option<DateTime<Utc>>,
    /// True iff `SELECT 1::int` returned successfully. False signals
    /// a complete pool / Postgres outage; the orchestrator de-rotates
    /// the pod until the DB recovers.
    pub db_reachable: bool,
    /// True iff `polaris_setup_state.did_document_updated_at IS NOT NULL`.
    /// Informational — `ready` does NOT depend on this so an operator
    /// can hit the setup wizard while traffic is being routed away.
    pub setup_complete: bool,
}

/// Handler for `GET /readyz`. Returns `200 OK` with the JSON body when
/// `ready == true`; `503 Service Unavailable` (same body) otherwise.
pub async fn handler(State(state): State<ApiState>) -> impl IntoResponse {
    let body = compute_readyz(&state).await;
    let status = if body.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
}

/// Derive the [`ReadyzBody`] from the live `ApiState`. Pulled out of
/// [`handler`] so a future internal admin / debug endpoint can render
/// the same body without going through axum.
async fn compute_readyz(state: &ApiState) -> ReadyzBody {
    let signing_key_provisioned = state.active_signer.as_ref().is_some_and(|rx| {
        let signer = rx.borrow();
        !signer.public_key_did().is_empty()
    });

    // `SELECT 1::int`: cheapest possible "is the DB reachable" probe.
    // Use `query_scalar` (not `query!`) because we don't need the
    // compile-time schema check — the literal `1::int` has a fixed
    // wire shape that sqlx encodes the same way at every Postgres
    // release.
    let db_reachable = sqlx::query_scalar::<_, i32>("SELECT 1::int")
        .fetch_one(&state.pool)
        .await
        .is_ok();

    // `last_emit_at` and `setup_complete` are best-effort: a DB
    // failure short-circuits them to `None` / `false`. The same query
    // failure already flips `db_reachable`, so the orchestrator sees
    // one consistent signal across all four fields.
    //
    // These two queries use the runtime `sqlx::query_scalar` / `query_as`
    // family (NOT the compile-time-checked `query!` / `query_as!` macro)
    // because their column projection is deliberately minimal — a single
    // typed column — and avoiding the macro keeps the `.sqlx/` offline
    // cache compact (the smoke-test postgres has known schema drift, so
    // adding new compile-time cache entries against it would block the
    // SQLX_OFFLINE=true build path until a `cargo sqlx prepare` round
    // trip is run against a clean DB).
    let last_emit_at: Option<DateTime<Utc>> = if db_reachable {
        match sqlx::query_scalar::<_, Option<DateTime<Utc>>>("SELECT MAX(signed_at) FROM labels")
            .fetch_one(&state.pool)
            .await
        {
            Ok(opt) => opt,
            Err(err) => {
                tracing::warn!(error = %err, "readyz: MAX(signed_at) probe failed");
                None
            }
        }
    } else {
        None
    };

    let setup_complete: bool = if db_reachable {
        match sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
            "SELECT did_document_updated_at FROM polaris_setup_state WHERE id = TRUE",
        )
        .fetch_optional(&state.pool)
        .await
        {
            Ok(row) => row.flatten().is_some(),
            Err(err) => {
                tracing::warn!(error = %err, "readyz: setup_state probe failed");
                false
            }
        }
    } else {
        false
    };

    ReadyzBody {
        ready: signing_key_provisioned && db_reachable,
        signing_key_provisioned,
        last_emit_at,
        db_reachable,
        setup_complete,
    }
}
