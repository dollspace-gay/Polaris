//! `EMAIL` moderator verb (issue #190 / Ozone-parity
//! `tools.ozone.moderation.defs#modEventEmail`).
//!
//! Sends an email to a moderator-supplied recipient address (typically
//! the subject's contact email) and records the delivery attempt in
//! `moderator_emails`. SMTP is optional: when the operator has not
//! configured `POLARIS_SMTP_HOST` the record is persisted with
//! `delivery_status = 'queued'` so the audit trail captures the
//! intent regardless. When SMTP is configured the handler delivers
//! via `lettre` and records the outcome (`sent` / `failed`).
//!
//! # Operator config
//!
//! - `POLARIS_SMTP_HOST` — SMTP relay hostname. Setting this enables
//!   live delivery; unsetting it keeps the verb in audit-only mode.
//! - `POLARIS_SMTP_PORT` — defaults to 587 (STARTTLS).
//! - `POLARIS_SMTP_USERNAME` / `POLARIS_SMTP_PASSWORD` — credentials
//!   for SMTP AUTH. Both must be set together; the handler refuses
//!   to send if one is present without the other.
//! - `POLARIS_SMTP_FROM` — `From:` address on outbound mail
//!   (`"Polaris Moderation <mod@example.org>"` shape).
//!
//! # Forbidden patterns
//!
//! - No PII in error logs: the recipient address goes into the row
//!   but only into `tracing::warn!` at fingerprint-level (first 3
//!   chars + domain), so log scrapers don't leak addressees.
//! - Parameterised SQL throughout.

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use polaris_types::SubjectId;
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;

/// Wire body for `POST /api/cases/{subject_id}/email`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendEmailBody {
    /// Recipient email address. Server enforces 3-320 chars (RFC
    /// 5321 max) and a single `@`.
    pub recipient_email: String,
    /// Email subject line. 1-998 chars (RFC 5322 max line length).
    pub subject_line: String,
    /// Plain-text body. 1-100,000 chars.
    pub body: String,
}

/// Wire shape for the persisted record echoed back to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeratorEmailRow {
    /// Stable identifier.
    pub id: uuid::Uuid,
    /// Subject this email was sent regarding (when known).
    pub subject_id: Option<SubjectId>,
    /// Subject DID at send time, for audit even after subject purge.
    pub subject_did: Option<String>,
    /// Moderator who sent the email.
    pub sent_by: uuid::Uuid,
    /// Recipient.
    pub recipient_email: String,
    /// Subject line.
    pub subject_line: String,
    /// Body.
    pub body: String,
    /// Delivery outcome.
    pub delivery_status: String,
    /// When delivery succeeded, if it did.
    pub delivered_at: Option<DateTime<Utc>>,
    /// Operator-readable error when `delivery_status == 'failed'`.
    pub delivery_error: Option<String>,
    /// When the record was created.
    pub created_at: DateTime<Utc>,
}

/// Response for `GET /api/cases/{subject_id}/emails`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailListResponse {
    /// Emails sent for this subject, newest-first.
    pub emails: Vec<ModeratorEmailRow>,
}

/// `POST /api/cases/{subject_id}/email` — send an email.
///
/// # Errors
///
/// * `400` when `recipient_email` is malformed or any field is out of
///   the column-CHECK range.
/// * `404` when `subject_id` doesn't exist (FK violation → mapped).
/// * `500` on DB failure. SMTP failures are NOT 500s — the record
///   is persisted with `delivery_status = 'failed'` and the caller
///   sees the row.
pub async fn send_email(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
    Json(body): Json<SendEmailBody>,
) -> Result<(StatusCode, Json<ModeratorEmailRow>), ApiError> {
    let recipient = body.recipient_email.trim();
    if !is_plausible_email(recipient) {
        return Err(ApiError::BadRequest("recipient_email is malformed"));
    }
    let subject_line = body.subject_line.trim();
    if subject_line.is_empty() {
        return Err(ApiError::BadRequest("subject_line must not be empty"));
    }
    if subject_line.len() > 998 {
        return Err(ApiError::BadRequest(
            "subject_line exceeds RFC-5322 max length",
        ));
    }
    let email_body = body.body.trim();
    if email_body.is_empty() {
        return Err(ApiError::BadRequest("body must not be empty"));
    }
    if email_body.len() > 100_000 {
        return Err(ApiError::BadRequest("body exceeds 100,000 character limit"));
    }

    // Resolve the subject's DID once so the audit row carries it
    // independently of the FK (FK uses ON DELETE SET NULL).
    let subject_did_row = sqlx::query!("SELECT did FROM subjects WHERE id = $1", subject_id.0,)
        .fetch_optional(&state.pool)
        .await
        .map_err(repo_err)?;
    let subject_did_text = subject_did_row.and_then(|r| r.did);

    // Attempt SMTP delivery if configured. Returns (status, error,
    // delivered_at). `delivered_at` is Some only on success.
    let (delivery_status, delivery_error, delivered_at) =
        attempt_smtp_delivery(recipient, subject_line, email_body).await;

    let row = sqlx::query!(
        r#"
        INSERT INTO moderator_emails
            (subject_id, subject_did, sent_by, recipient_email,
             subject_line, body, delivery_status, delivered_at,
             delivery_error)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, subject_id, subject_did, sent_by, recipient_email,
                  subject_line, body, delivery_status, delivered_at,
                  delivery_error, created_at
        "#,
        subject_id.0,
        subject_did_text.as_deref(),
        ctx.moderator_id.0,
        recipient,
        subject_line,
        email_body,
        delivery_status,
        delivered_at,
        delivery_error.as_deref(),
    )
    .fetch_one(&state.pool)
    .await
    .map_err(map_fk_or_repo)?;

    tracing::info!(
        email_id = %row.id,
        subject_id = %subject_id.0,
        recipient_fp = %fingerprint(&row.recipient_email),
        delivery_status = %row.delivery_status,
        "moderator email recorded",
    );

    Ok((
        StatusCode::CREATED,
        Json(ModeratorEmailRow {
            id: row.id,
            subject_id: row.subject_id.map(SubjectId),
            subject_did: row.subject_did,
            sent_by: row.sent_by,
            recipient_email: row.recipient_email,
            subject_line: row.subject_line,
            body: row.body,
            delivery_status: row.delivery_status,
            delivered_at: row.delivered_at,
            delivery_error: row.delivery_error,
            created_at: row.created_at,
        }),
    ))
}

/// `GET /api/cases/{subject_id}/emails` — list emails sent for a
/// subject, newest-first.
pub async fn list_emails(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
) -> Result<Json<EmailListResponse>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, subject_id, subject_did, sent_by, recipient_email,
               subject_line, body, delivery_status, delivered_at,
               delivery_error, created_at
        FROM moderator_emails
        WHERE subject_id = $1
        ORDER BY created_at DESC
        LIMIT 200
        "#,
        subject_id.0,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(repo_err)?;
    let emails = rows
        .into_iter()
        .map(|r| ModeratorEmailRow {
            id: r.id,
            subject_id: r.subject_id.map(SubjectId),
            subject_did: r.subject_did,
            sent_by: r.sent_by,
            recipient_email: r.recipient_email,
            subject_line: r.subject_line,
            body: r.body,
            delivery_status: r.delivery_status,
            delivered_at: r.delivered_at,
            delivery_error: r.delivery_error,
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(EmailListResponse { emails }))
}

/// Attempt SMTP delivery via `lettre` if the operator has configured
/// SMTP. Returns `(status, error_message, delivered_at)`:
///
/// * SMTP unconfigured → `("queued", None, None)`.
/// * Delivery succeeds → `("sent", None, Some(now))`.
/// * Delivery fails → `("failed", Some(error), None)`.
///
/// This is best-effort: a non-fatal SMTP failure (relay down, auth
/// rejection) is recorded in the row but doesn't surface as a 5xx
/// to the moderator. The handler returns 201 with the failed-row
/// payload so the UI can render "queued for retry" / "delivery
/// failed" inline.
#[allow(
    clippy::too_many_lines,
    reason = "linear top-to-bottom SMTP-delivery state machine: env-read, \
              mailbox parse, transport build, credentials, send. Each step \
              has an inline fallback branch; extracting them into helpers \
              would push the early-returns across functions and obscure the \
              control flow."
)]
async fn attempt_smtp_delivery(
    recipient: &str,
    subject_line: &str,
    body: &str,
) -> (String, Option<String>, Option<DateTime<Utc>>) {
    use lettre::AsyncTransport;
    use lettre::Message;
    use lettre::Tokio1Executor;
    use lettre::message::Mailbox;
    use lettre::transport::smtp::AsyncSmtpTransport;
    use lettre::transport::smtp::authentication::Credentials;
    use std::str::FromStr;

    let Ok(host) = std::env::var("POLARIS_SMTP_HOST") else {
        // Audit-only mode: SMTP not configured.
        return ("queued".to_owned(), None, None);
    };
    if host.trim().is_empty() {
        return ("queued".to_owned(), None, None);
    }

    let port: u16 = std::env::var("POLARIS_SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(587);
    let Ok(from) = std::env::var("POLARIS_SMTP_FROM") else {
        return (
            "failed".to_owned(),
            Some("POLARIS_SMTP_FROM not configured".to_owned()),
            None,
        );
    };

    let from_mbox = match Mailbox::from_str(&from) {
        Ok(m) => m,
        Err(e) => {
            return (
                "failed".to_owned(),
                Some(format!("POLARIS_SMTP_FROM is malformed: {e}")),
                None,
            );
        }
    };
    let to_mbox = match Mailbox::from_str(recipient) {
        Ok(m) => m,
        Err(e) => {
            return (
                "failed".to_owned(),
                Some(format!("recipient address parse failed: {e}")),
                None,
            );
        }
    };
    let message = match Message::builder()
        .from(from_mbox)
        .to(to_mbox)
        .subject(subject_line)
        .body(body.to_owned())
    {
        Ok(m) => m,
        Err(e) => {
            return (
                "failed".to_owned(),
                Some(format!("message build failed: {e}")),
                None,
            );
        }
    };

    let mut builder = match AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host) {
        Ok(b) => b.port(port),
        Err(e) => {
            return (
                "failed".to_owned(),
                Some(format!("smtp transport build failed: {e}")),
                None,
            );
        }
    };

    // Credentials are optional but BOTH or NEITHER — refuse to send
    // with only half the auth tuple.
    let user = std::env::var("POLARIS_SMTP_USERNAME").ok();
    let pass = std::env::var("POLARIS_SMTP_PASSWORD").ok();
    match (user, pass) {
        (Some(u), Some(p)) => {
            builder = builder.credentials(Credentials::new(u, p));
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return (
                "failed".to_owned(),
                Some(
                    "POLARIS_SMTP_USERNAME and POLARIS_SMTP_PASSWORD must both be set or both unset"
                        .to_owned(),
                ),
                None,
            );
        }
    }

    let transport = builder.build();
    match transport.send(message).await {
        Ok(_) => ("sent".to_owned(), None, Some(Utc::now())),
        Err(e) => (
            "failed".to_owned(),
            Some(format!("smtp send failed: {e}")),
            None,
        ),
    }
}

/// Minimal sanity check on an email address. The handler enforces
/// presence + position of `@`, length bounds, and no whitespace.
/// Full RFC 5322 validation is intentionally out of scope — the
/// SMTP server is the authoritative validator and any malformed
/// address that survives this check surfaces as `delivery_status =
/// 'failed'` with the underlying SMTP error.
fn is_plausible_email(s: &str) -> bool {
    if s.len() < 3 || s.len() > 320 {
        return false;
    }
    if s.chars().any(char::is_whitespace) {
        return false;
    }
    let at_count = s.bytes().filter(|b| *b == b'@').count();
    if at_count != 1 {
        return false;
    }
    let mut parts = s.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

/// Produce a redacted, log-safe fingerprint of an email address:
/// `abc***@example.com`. The first three local-part chars plus the
/// full domain. Used in `tracing::info!` so log readers can correlate
/// without leaking the full addressee.
fn fingerprint(email: &str) -> String {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    let local_prefix: String = local.chars().take(3).collect();
    format!("{local_prefix}***@{domain}")
}

fn repo_err(e: sqlx::Error) -> ApiError {
    ApiError::Repo(crate::repo::RepoError::from(e))
}

fn map_fk_or_repo(e: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(db) = &e {
        if db.code().as_deref() == Some("23503") {
            return ApiError::NotFound;
        }
    }
    repo_err(e)
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
    fn plausible_email_accepts_basic_form() {
        assert!(is_plausible_email("alice@example.com"));
        assert!(is_plausible_email("a@b.co"));
        assert!(is_plausible_email("test.user+tag@sub.example.org"));
    }

    #[test]
    fn plausible_email_rejects_malformed() {
        assert!(!is_plausible_email(""));
        assert!(!is_plausible_email("no-at-sign"));
        assert!(!is_plausible_email("two@ats@example.com"));
        assert!(!is_plausible_email("@example.com"));
        assert!(!is_plausible_email("alice@"));
        assert!(!is_plausible_email("alice@no-dot-domain"));
        assert!(!is_plausible_email("has spaces@example.com"));
    }

    #[test]
    fn fingerprint_redacts_local_part() {
        assert_eq!(fingerprint("alice@example.com"), "ali***@example.com");
        assert_eq!(fingerprint("ab@example.com"), "ab***@example.com");
        assert_eq!(fingerprint("a@example.com"), "a***@example.com");
    }
}
