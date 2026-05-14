//! Second-opinion thread repository (issue #25).
//!
//! Maps the `second_opinion_threads` / `second_opinion_messages` tables
//! from migration `00000000000011_second_opinion.sql` to typed Rust
//! values, with a full-text-search projection over message bodies.
//!
//! # Append-only by construction
//!
//! [`SecondOpinionRepo`] exposes only `open_thread`, `append_message`,
//! `get_thread_with_messages`, and `search` — no `update_message` of
//! any kind. Edits go through a new row carrying `replaces_message_id`,
//! and the DB trigger from migration 11 rejects any direct UPDATE with
//! SQLSTATE `P0001`. The [`crate::repo::RepoError::AppendOnlyViolation`]
//! variant is how a bypass would surface to a caller.
//!
//! # Parameterised search queries
//!
//! [`SecondOpinionRepo::search`] uses `plainto_tsquery($1)` with the
//! user-supplied query bound as a parameter through `sqlx::query!`. That
//! is the *only* tsquery construction in this module; there is no string
//! concatenation, no `format!`, no `query_unchecked`. The architect's
//! pre-flight #25 forbids string-built tsquery, and this design makes
//! that forbidden pattern mechanically impossible at the repo layer.
//!
//! # Why local newtypes for `ThreadId` / `MessageId`
//!
//! `polaris-types` declares the wire-shared identifier types
//! (`SubjectId`, `IncidentId`, `ActionId`, `AppealId`, …). The
//! second-opinion thread / message ids are also wire-shared (they are
//! returned by the API), but the architect's #25 scope deliberately
//! omits the frontend UI panel. Rather than reach into `polaris-types`
//! for two newtypes that only the backend touches today, the IDs live
//! here with the same shape (transparent `Uuid` newtype, serde-
//! transparent, `Default` mints a fresh v4). A later issue that lands
//! the frontend can promote them to `polaris-types` without changing
//! any wire form.

use chrono::{DateTime, Utc};
use polaris_types::{ActionId, IncidentId, ModeratorId};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use super::RepoError;

// ── IDs ────────────────────────────────────────────────────────────────

/// Identifier for a second-opinion thread row.
///
/// The wire form is the bare UUID string (`serde(transparent)`),
/// matching the convention used by the other typed ids in
/// `polaris-types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThreadId(pub Uuid);

impl ThreadId {
    /// Mint a fresh v4 UUID-backed thread id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Borrow the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Consume the id and return the inner UUID.
    #[must_use]
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ThreadId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<Uuid> for ThreadId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<ThreadId> for Uuid {
    fn from(value: ThreadId) -> Self {
        value.0
    }
}

/// Identifier for a second-opinion message row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessageId(pub Uuid);

impl MessageId {
    /// Mint a fresh v4 UUID-backed message id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Borrow the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Consume the id and return the inner UUID.
    #[must_use]
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<Uuid> for MessageId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<MessageId> for Uuid {
    fn from(value: MessageId) -> Self {
        value.0
    }
}

// ── domain rows ────────────────────────────────────────────────────────

/// A `second_opinion_threads` row.
///
/// `draft_action_id` is `None` for threads opened in the abstract
/// (no concrete draft action attached at open time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    /// Primary key.
    pub id: ThreadId,
    /// Host incident — the thread is attached to this incident's
    /// case-view side-panel.
    pub incident_id: IncidentId,
    /// Moderator who opened the thread.
    pub requested_by: ModeratorId,
    /// Optional pointer at the draft action that triggered the flag.
    pub draft_action_id: Option<ActionId>,
    /// When the thread was opened.
    pub opened_at: DateTime<Utc>,
}

/// A `second_opinion_messages` row.
///
/// Stored append-only; edits write a new row with `replaces_message_id`
/// pointing at the row being amended. The DB trigger from migration 11
/// rejects any UPDATE against this table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Primary key.
    pub id: MessageId,
    /// Containing thread.
    pub thread_id: ThreadId,
    /// Author of the message.
    pub moderator_id: ModeratorId,
    /// Free-text body. Validated `[1, 16384]` chars at the API layer;
    /// the DB CHECK constraint enforces the same bound as defense in
    /// depth.
    pub body: String,
    /// `Some(id)` when this row amends an earlier message; `None` for
    /// freshly composed messages.
    pub replaces_message_id: Option<MessageId>,
    /// When the row was written.
    pub created_at: DateTime<Utc>,
}

/// A single hit from [`SecondOpinionRepo::search`].
///
/// Carries the message + its parent thread id + the `ts_rank_cd` score
/// so the caller can sort or threshold without re-querying.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    /// The matching message.
    pub message: Message,
    /// `ts_rank_cd(body_tsv, plainto_tsquery($q))`. Higher is a better
    /// match. The exact value is opaque per the Postgres docs — only
    /// the *ordering* among hits is meaningful.
    pub rank: f32,
}

// ── trait ──────────────────────────────────────────────────────────────

/// Compile-time contract for the second-opinion repository.
///
/// Every method takes `&self` (the underlying `sqlx::PgPool` is
/// internally `Arc`-shared, so the repo is cheap to clone) and returns
/// futures bounded by `Send` for axum compatibility.
pub trait SecondOpinionRepo: Send + Sync {
    /// Open a new thread on `incident_id`, requested by
    /// `requested_by`. `draft_action_id` is the optional pointer at the
    /// draft action that triggered the flag.
    ///
    /// Returns the freshly-minted [`ThreadId`].
    fn open_thread(
        &self,
        incident_id: IncidentId,
        requested_by: ModeratorId,
        draft_action_id: Option<ActionId>,
    ) -> impl std::future::Future<Output = Result<ThreadId, RepoError>> + Send;

    /// Append a message to `thread_id` authored by `moderator_id`.
    ///
    /// `replaces` carries the optional `replaces_message_id` pointer for
    /// the edit-via-new-row pattern. Callers compose a *new* message
    /// rather than mutate an existing one — the DB trigger on
    /// `second_opinion_messages` rejects any UPDATE with SQLSTATE
    /// `P0001`.
    ///
    /// Returns the new [`MessageId`].
    fn append_message(
        &self,
        thread_id: ThreadId,
        moderator_id: ModeratorId,
        body: String,
        replaces: Option<MessageId>,
    ) -> impl std::future::Future<Output = Result<MessageId, RepoError>> + Send;

    /// Look up a thread + its messages in chronological order. Returns
    /// `Ok(None)` when the thread does not exist.
    fn get_thread_with_messages(
        &self,
        thread_id: ThreadId,
    ) -> impl std::future::Future<Output = Result<Option<(Thread, Vec<Message>)>, RepoError>> + Send;

    /// Full-text search over message bodies.
    ///
    /// `query` is a plain natural-language string. The repo passes it
    /// to `plainto_tsquery($1)` as a bound parameter, so tsquery syntax
    /// in user input is interpreted as literal text — no operator
    /// injection.
    ///
    /// `limit` is capped server-side; values ≤ 0 short-circuit to an
    /// empty result so the caller never accidentally drives an
    /// unbounded scan.
    fn search(
        &self,
        query: &str,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<SearchHit>, RepoError>> + Send;
}

// ── pg impl ────────────────────────────────────────────────────────────

/// Postgres-backed [`SecondOpinionRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgSecondOpinionRepo {
    pool: PgPool,
}

impl PgSecondOpinionRepo {
    /// Build a [`PgSecondOpinionRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SecondOpinionRepo for PgSecondOpinionRepo {
    async fn open_thread(
        &self,
        incident_id: IncidentId,
        requested_by: ModeratorId,
        draft_action_id: Option<ActionId>,
    ) -> Result<ThreadId, RepoError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO second_opinion_threads (
                incident_id, requested_by, draft_action_id
            )
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            incident_id.0,
            requested_by.0,
            draft_action_id.map(|a| a.0),
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(ThreadId(row.id))
    }

    async fn append_message(
        &self,
        thread_id: ThreadId,
        moderator_id: ModeratorId,
        body: String,
        replaces: Option<MessageId>,
    ) -> Result<MessageId, RepoError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO second_opinion_messages (
                thread_id, moderator_id, body, replaces_message_id
            )
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
            thread_id.0,
            moderator_id.0,
            body,
            replaces.map(|m| m.0),
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(MessageId(row.id))
    }

    async fn get_thread_with_messages(
        &self,
        thread_id: ThreadId,
    ) -> Result<Option<(Thread, Vec<Message>)>, RepoError> {
        let Some(thread_row) = sqlx::query!(
            r#"
            SELECT id, incident_id, requested_by, draft_action_id, opened_at
            FROM second_opinion_threads
            WHERE id = $1
            "#,
            thread_id.0,
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };

        let message_rows = sqlx::query!(
            r#"
            SELECT id, thread_id, moderator_id, body, replaces_message_id, created_at
            FROM second_opinion_messages
            WHERE thread_id = $1
            ORDER BY created_at ASC, id ASC
            "#,
            thread_id.0,
        )
        .fetch_all(&self.pool)
        .await?;

        let thread = Thread {
            id: ThreadId(thread_row.id),
            incident_id: IncidentId(thread_row.incident_id),
            requested_by: ModeratorId(thread_row.requested_by),
            draft_action_id: thread_row.draft_action_id.map(ActionId),
            opened_at: thread_row.opened_at,
        };
        let messages = message_rows
            .into_iter()
            .map(|row| Message {
                id: MessageId(row.id),
                thread_id: ThreadId(row.thread_id),
                moderator_id: ModeratorId(row.moderator_id),
                body: row.body,
                replaces_message_id: row.replaces_message_id.map(MessageId),
                created_at: row.created_at,
            })
            .collect();
        Ok(Some((thread, messages)))
    }

    async fn search(&self, query: &str, limit: i64) -> Result<Vec<SearchHit>, RepoError> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        // `plainto_tsquery('english', $1)` accepts arbitrary user text
        // and yields a tsquery whose operators come *only* from the
        // configuration's parser — operator-injection through `&`, `|`,
        // `<->`, `!` in the input is mechanically impossible.
        //
        // `ts_rank_cd` returns a `real` (f32). We `SELECT … AS "rank!"`
        // so sqlx infers a non-null `f32` (the expression is never NULL
        // for a row that matched the `@@` filter).
        let rows = sqlx::query!(
            r#"
            SELECT id, thread_id, moderator_id, body, replaces_message_id, created_at,
                   ts_rank_cd(body_tsv, plainto_tsquery('english', $1)) AS "rank!: f32"
            FROM second_opinion_messages
            WHERE body_tsv @@ plainto_tsquery('english', $1)
            ORDER BY ts_rank_cd(body_tsv, plainto_tsquery('english', $1)) DESC,
                     created_at DESC, id ASC
            LIMIT $2
            "#,
            query,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| SearchHit {
                message: Message {
                    id: MessageId(row.id),
                    thread_id: ThreadId(row.thread_id),
                    moderator_id: ModeratorId(row.moderator_id),
                    body: row.body,
                    replaces_message_id: row.replaces_message_id.map(MessageId),
                    created_at: row.created_at,
                },
                rank: row.rank,
            })
            .collect())
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
    fn thread_id_round_trips_through_serde() {
        let id = ThreadId::new();
        let json = serde_json::to_string(&id).expect("serialize");
        let back: ThreadId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, back);
    }

    #[test]
    fn message_id_round_trips_through_serde() {
        let id = MessageId::new();
        let json = serde_json::to_string(&id).expect("serialize");
        let back: MessageId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, back);
    }

    #[test]
    fn thread_id_default_mints_fresh_uuid() {
        let a = ThreadId::default();
        let b = ThreadId::default();
        assert_ne!(a, b, "Default must mint a fresh v4 UUID, not zero");
    }

    #[test]
    fn message_id_default_mints_fresh_uuid() {
        let a = MessageId::default();
        let b = MessageId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn thread_id_display_matches_uuid_canonical_form() {
        let inner = Uuid::new_v4();
        assert_eq!(ThreadId(inner).to_string(), inner.to_string());
    }

    #[test]
    fn message_id_display_matches_uuid_canonical_form() {
        let inner = Uuid::new_v4();
        assert_eq!(MessageId(inner).to_string(), inner.to_string());
    }
}
