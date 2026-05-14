//! Second-opinion thread API (issue #25).
//!
//! Per `design.md` §5.6: "One-click flag for senior review. The senior
//! moderator sees the case with the original moderator's draft action
//! and reasoning. Their conversation about the decision is attached to
//! the incident permanently, becoming searchable training material for
//! future moderators."
//!
//! # Four endpoints, all authenticated
//!
//! 1. `POST /api/incidents/:incident_id/second-opinion` —
//!    [`open_thread`]. Opens a fresh thread on the host incident and
//!    appends the initial message in a single call. Body carries the
//!    optional draft-action pointer plus the initial message text.
//!
//! 2. `POST /api/threads/:thread_id/messages` — [`append_message`].
//!    Appends a message to an existing thread. Body carries the message
//!    text and an optional `replaces` pointer for the edit-via-new-row
//!    pattern.
//!
//! 3. `GET /api/threads/search?q=…` — [`search_threads`]. Full-text
//!    search over message bodies. `q` is bound as a parameter to
//!    `plainto_tsquery`; tsquery operators in user input are interpreted
//!    as literal text (no injection surface).
//!
//! 4. `GET /api/threads/:thread_id` — [`get_thread`]. Returns the
//!    thread row plus its messages in chronological order.
//!
//! # Forbidden patterns (architect's pre-flight)
//!
//! - **No string-built SQL.** Every query goes through `sqlx::query!`
//!   in the repo; the API layer never builds SQL.
//! - **No UPDATE on `second_opinion_messages`.** Edits write a new row
//!   via the `replaces` pointer; the DB trigger from migration 11
//!   rejects any UPDATE with SQLSTATE `P0001`.
//! - **No `unwrap` / `expect` outside `#[cfg(test)]`.** All fallible
//!   work returns `Result<_, ApiError>`.
//! - **No `anyhow` on a public signature.** The handler exit type is
//!   `ApiError`, the workspace's typed `thiserror` enum.
//! - **No `unsafe`** (denied workspace-wide).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use polaris_types::{ActionId, IncidentId, ModeratorId};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;
use crate::repo::{Message, SearchHit, SecondOpinionRepo, Thread, ThreadId};

/// Minimum allowed message body length (chars). Matches the DB CHECK
/// constraint in `00000000000011_second_opinion.sql`.
pub const MIN_BODY_LEN: usize = 1;

/// Maximum allowed message body length (chars). Matches the DB CHECK
/// constraint in `00000000000011_second_opinion.sql`.
pub const MAX_BODY_LEN: usize = 16_384;

/// Maximum number of search hits returned by the `GET /api/threads/search`
/// endpoint, regardless of any caller-supplied bound. Search is a hot
/// path; a fixed ceiling stops a pathological query from monopolising the
/// pool.
pub const MAX_SEARCH_LIMIT: i64 = 100;

/// Default search limit when the caller omits the `limit` query parameter.
pub const DEFAULT_SEARCH_LIMIT: i64 = 25;

// ── DTOs ───────────────────────────────────────────────────────────────

/// Wire shape for `POST /api/incidents/:incident_id/second-opinion`.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenThreadBody {
    /// Optional pointer at the draft action that triggered the flag.
    pub draft_action_id: Option<ActionId>,
    /// Initial message text. Validated `[MIN_BODY_LEN, MAX_BODY_LEN]`
    /// at the API; the DB CHECK enforces the same bound as defense in
    /// depth.
    pub initial_message: String,
}

/// Wire shape for the 201 response of
/// `POST /api/incidents/:incident_id/second-opinion`.
#[derive(Debug, Clone, Serialize)]
pub struct OpenedThread {
    /// The newly-minted thread id.
    pub thread_id: ThreadId,
    /// The id of the initial message that was appended in the same call.
    pub initial_message_id: crate::repo::MessageId,
}

/// Wire shape for `POST /api/threads/:thread_id/messages`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppendMessageBody {
    /// Message text. Validated `[MIN_BODY_LEN, MAX_BODY_LEN]` at the
    /// API layer.
    pub body: String,
    /// Optional pointer at the message this row amends. The original
    /// row is NOT mutated — the audit chain stays intact.
    pub replaces: Option<crate::repo::MessageId>,
}

/// Wire shape for the 201 response of
/// `POST /api/threads/:thread_id/messages`.
#[derive(Debug, Clone, Serialize)]
pub struct AppendedMessage {
    /// The new message id.
    pub message_id: crate::repo::MessageId,
}

/// Wire shape for the query parameters of `GET /api/threads/search`.
#[derive(Debug, Clone, Deserialize)]
pub struct SearchQuery {
    /// Free-text search query. Passed verbatim to `plainto_tsquery`
    /// through a bound parameter — tsquery syntax in user input is
    /// interpreted as literal text.
    pub q: String,
    /// Optional per-call limit. Capped server-side at
    /// [`MAX_SEARCH_LIMIT`]; defaulted to [`DEFAULT_SEARCH_LIMIT`] when
    /// absent.
    pub limit: Option<i64>,
}

/// Wire shape for the 200 response of `GET /api/threads/search`.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResults {
    /// Hits sorted by `ts_rank_cd` descending then by `created_at`
    /// descending.
    pub hits: Vec<SearchHit>,
}

/// Wire shape for the 200 response of `GET /api/threads/:thread_id`.
#[derive(Debug, Clone, Serialize)]
pub struct ThreadView {
    /// The thread row.
    pub thread: Thread,
    /// All messages on the thread in chronological order.
    pub messages: Vec<Message>,
}

// ── validation ─────────────────────────────────────────────────────────

/// Validate a message body. Length is counted in chars (matching the
/// DB CHECK's `length(body)`, which counts characters for `TEXT`).
pub(crate) fn validate_body(body: &str) -> Result<(), ApiError> {
    let len = body.chars().count();
    if len < MIN_BODY_LEN {
        return Err(ApiError::BadRequest(
            "second-opinion message body must be non-empty",
        ));
    }
    if len > MAX_BODY_LEN {
        return Err(ApiError::BadRequest(
            "second-opinion message body exceeds 16384-char cap",
        ));
    }
    Ok(())
}

/// Normalise the caller-supplied search limit. `None` → default; values
/// above the ceiling are clamped; non-positive values are rejected with
/// `BadRequest`.
pub(crate) fn normalize_search_limit(limit: Option<i64>) -> Result<i64, ApiError> {
    match limit {
        None => Ok(DEFAULT_SEARCH_LIMIT),
        Some(n) if n <= 0 => Err(ApiError::BadRequest("limit must be positive")),
        Some(n) => Ok(n.min(MAX_SEARCH_LIMIT)),
    }
}

// ── handlers ───────────────────────────────────────────────────────────

/// Handler: `POST /api/incidents/:incident_id/second-opinion`.
///
/// Opens a fresh thread on the host incident and appends the initial
/// message in one round trip. The author identity comes from the
/// authenticated session ([`ModeratorAuthCtx`]), NOT from the request
/// body — that is the §6 AC-7 attribution contract.
///
/// # Errors
///
/// - `400 Bad Request` — `initial_message` empty / over the 16384-char
///   cap.
/// - `404 Not Found` — `incident_id` does not exist (FK violation
///   routed via [`crate::repo::RepoError::ForeignKey`]).
/// - `500 Internal Server Error` — DB failure.
pub async fn open_thread(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(incident_id): Path<IncidentId>,
    Json(body): Json<OpenThreadBody>,
) -> Result<(StatusCode, Json<OpenedThread>), ApiError> {
    validate_body(&body.initial_message)?;
    let moderator_id = ModeratorId(ctx.moderator_id.0);
    let thread_id = state
        .second_opinion
        .open_thread(incident_id, moderator_id, body.draft_action_id)
        .await
        .map_err(map_repo_to_api)?;
    let initial_message_id = state
        .second_opinion
        .append_message(thread_id, moderator_id, body.initial_message, None)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(OpenedThread {
            thread_id,
            initial_message_id,
        }),
    ))
}

/// Handler: `POST /api/threads/:thread_id/messages`.
///
/// Appends a message to an existing thread. Edits go through this same
/// path with `replaces = Some(id)`; the DB never sees an UPDATE on
/// `second_opinion_messages`.
///
/// # Errors
///
/// - `400 Bad Request` — `body` empty / over the 16384-char cap.
/// - `404 Not Found` — `thread_id` does not exist, or `replaces`
///   points at a non-existent message (FK violation).
/// - `500 Internal Server Error` — DB failure.
pub async fn append_message(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(thread_id): Path<ThreadId>,
    Json(body): Json<AppendMessageBody>,
) -> Result<(StatusCode, Json<AppendedMessage>), ApiError> {
    validate_body(&body.body)?;
    let moderator_id = ModeratorId(ctx.moderator_id.0);
    let message_id = state
        .second_opinion
        .append_message(thread_id, moderator_id, body.body, body.replaces)
        .await
        .map_err(map_repo_to_api)?;
    Ok((StatusCode::CREATED, Json(AppendedMessage { message_id })))
}

/// Handler: `GET /api/threads/search?q=…&limit=…`.
///
/// Full-text search over every message body. `q` is bound through
/// `plainto_tsquery($1)` in the repo; tsquery syntax in `q` is treated
/// as literal text. The architect's pre-flight #25 forbids string-built
/// tsquery, and this code path makes that mechanically impossible —
/// there is no construction of a tsquery string anywhere.
///
/// # Errors
///
/// - `400 Bad Request` — `limit` non-positive.
/// - `500 Internal Server Error` — DB failure.
pub async fn search_threads(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<SearchResults>, ApiError> {
    let limit = normalize_search_limit(q.limit)?;
    let hits = state.second_opinion.search(&q.q, limit).await?;
    Ok(Json(SearchResults { hits }))
}

/// Handler: `GET /api/threads/:thread_id`.
///
/// Returns the thread plus its messages in chronological order.
///
/// # Errors
///
/// - `404 Not Found` — `thread_id` does not exist.
/// - `500 Internal Server Error` — DB failure.
pub async fn get_thread(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(thread_id): Path<ThreadId>,
) -> Result<Json<ThreadView>, ApiError> {
    let (thread, messages) = state
        .second_opinion
        .get_thread_with_messages(thread_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(ThreadView { thread, messages }))
}

// ── helpers ────────────────────────────────────────────────────────────

/// Map a [`crate::repo::RepoError`] to an [`ApiError`].
///
/// `ForeignKey` becomes `404 Not Found` because the only FKs in this
/// module are `incident_id` / `thread_id` / `replaces_message_id` /
/// `moderator_id`; a violation means the caller referenced a row that
/// does not exist. `AppendOnlyViolation` is impossible on the insert
/// path (the trigger fires only on UPDATE) but is mapped to `Conflict`
/// for completeness — surfacing the typed signal if a future code path
/// somehow triggered it. Other variants fall through to the default
/// `Repo` rendering.
fn map_repo_to_api(err: crate::repo::RepoError) -> ApiError {
    use crate::repo::RepoError;
    match err {
        RepoError::ForeignKey(_) | RepoError::NotFound => ApiError::NotFound,
        RepoError::AppendOnlyViolation(_) => {
            ApiError::Conflict("second-opinion messages are append-only")
        }
        other => ApiError::Repo(other),
    }
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

    #[test]
    fn validate_body_accepts_short_text() {
        validate_body("hi").expect("normal text");
    }

    #[test]
    fn validate_body_rejects_empty() {
        let err = validate_body("").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_body_accepts_max_length() {
        let max = "a".repeat(MAX_BODY_LEN);
        validate_body(&max).expect("at-the-cap length is valid");
    }

    #[test]
    fn validate_body_rejects_over_cap() {
        let over = "a".repeat(MAX_BODY_LEN + 1);
        let err = validate_body(&over).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("16384")),
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn validate_body_counts_chars_not_bytes() {
        // A 4-byte UTF-8 character ('𝒜', U+1D49C) counts as one char.
        // 16384 copies sits exactly at the char cap; 16385 trips.
        let ok = "\u{1D49C}".repeat(MAX_BODY_LEN);
        validate_body(&ok).expect("16384 chars must pass (regardless of byte length)");
        let bad = "\u{1D49C}".repeat(MAX_BODY_LEN + 1);
        validate_body(&bad).unwrap_err();
    }

    #[test]
    fn normalize_search_limit_defaults_when_absent() {
        assert_eq!(normalize_search_limit(None).unwrap(), DEFAULT_SEARCH_LIMIT);
    }

    #[test]
    fn normalize_search_limit_clamps_to_ceiling() {
        assert_eq!(
            normalize_search_limit(Some(MAX_SEARCH_LIMIT + 1)).unwrap(),
            MAX_SEARCH_LIMIT,
        );
    }

    #[test]
    fn normalize_search_limit_rejects_zero_and_negative() {
        for n in [0_i64, -1, i64::MIN] {
            let err = normalize_search_limit(Some(n)).unwrap_err();
            assert!(matches!(err, ApiError::BadRequest(_)));
        }
    }

    #[test]
    fn normalize_search_limit_preserves_value_below_ceiling() {
        assert_eq!(normalize_search_limit(Some(7)).unwrap(), 7);
    }

    #[test]
    fn map_repo_to_api_routes_foreign_key_to_not_found() {
        // We can't easily construct a real sqlx ForeignKey error in a
        // unit test, but we can prove the NotFound arm directly.
        let mapped = map_repo_to_api(crate::repo::RepoError::NotFound);
        assert!(matches!(mapped, ApiError::NotFound));
    }
}
