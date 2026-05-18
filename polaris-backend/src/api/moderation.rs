//! Inbound moderation reports — `com.atproto.moderation.createReport`.
//!
//! Bsky.app users tap "Report" against the Polaris labeler; their client
//! POSTs `/xrpc/com.atproto.moderation.createReport` with a service-auth
//! JWT (`Authorization: Bearer <jwt>`) identifying the reporter and a
//! JSON body describing the subject + category. Without a handler at
//! this route Polaris returns 404 and bsky.app surfaces "something went
//! wrong, please try again" to the reporter — the symptom that motivated
//! this module.
//!
//! # Wire shape
//!
//! Input / Output are the generated lexicon types from
//! `proto_blue::api::generated::com::atproto::moderation::createReport`.
//! Input variants:
//!
//! - `subject: { $type: "com.atproto.admin.defs#repoRef", did }` — an
//!   account-level report. The DID becomes the subject row's DID.
//! - `subject: { $type: "com.atproto.repo.strongRef", uri, cid }` — a
//!   record-level (post / list / feed) report. The authoring DID is
//!   extracted from the AT-URI; both `did` and `uri` populate the
//!   subject row.
//!
//! # Reporter identity
//!
//! The bsky.app client signs a short-lived JWT whose `iss` claim is the
//! reporter's DID. **Signature verification is currently DEFERRED**:
//! this handler decodes the JWT payload and trusts the `iss` claim
//! without cryptographic verification. A follow-up issue must wire the
//! reporter's signing key from PLC + verify the JWT signature before
//! production deployment to a public host (otherwise anyone can submit
//! reports under any DID). The trade-off is documented at
//! [`extract_reporter_did_unverified`].
//!
//! # Rate limiting
//!
//! IP-keyed rate limiting via the existing `state.appeals_rate_limiter`
//! covers anonymous floods. Reporter-DID rate limiting belongs in a
//! follow-up once the JWT signature is verified.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use polaris_types::{AtUri, Did, ReportCategory, SubjectKind};
use proto_blue::api::generated::com::atproto::moderation::create_report::{
    Input, InputSubjectRefs, Output, OutputSubjectRefs,
};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::api::subjects::{ResolvedSubject, find_or_insert_subject};
// Repo's `NewReport` is structurally identical to
// `polaris_types::NewReport` but distinct at the type level; the
// `ReportRepo::insert` trait takes the repo's version, so we import
// it under an explicit alias to make the mismatch impossible to
// trip into.
use crate::repo::NewReport as RepoNewReport;
use crate::repo::ReportRepo as _;

/// Maximum length of the reporter-supplied free-text `reason` field.
/// Matches the lexicon's `maxGraphemes: 2000` / `maxLength: 20000`
/// bound; we enforce the latter (bytes), which is also what we
/// persist in `reports.body`.
const REASON_MAX_BYTES: usize = 20_000;

/// axum handler for `POST /xrpc/com.atproto.moderation.createReport`.
///
/// Mounted on the public router (no Polaris session cookie required)
/// because the reporter is an external bsky.app user, not a Polaris
/// moderator. IP-rate-limited via `state.appeals_rate_limiter` so a
/// runaway client cannot flood the partition.
///
/// # Errors
///
/// * `400 Bad Request` — missing/malformed Authorization header,
///   subject variant not understood, AT-URI cannot be parsed for an
///   authoring DID, or `reason` exceeds [`REASON_MAX_BYTES`].
/// * `429 Too Many Requests` — IP quota exhausted.
/// * `500 Internal Server Error` — DB failure.
pub async fn create_report(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> Result<Json<Output>, ApiError> {
    state.appeals_rate_limiter.try_consume(addr.ip()).await?;

    let reporter_did = extract_reporter_did_unverified(&headers)?;

    // Issue #192: muted-reporters check. Spammy or weaponised DIDs
    // have their inbound reports SILENTLY dropped — the response
    // shape is identical to a successful submission so the muting
    // is not leaked to the muted reporter (which would let them
    // probe for the mute and rotate DIDs). The fabricated id is
    // derived from the (DID, timestamp) tuple so a single muted
    // reporter retrying the same payload sees a different id each
    // time and cannot detect the silent drop by id-equality.
    if crate::api::moderator_controls::is_reporter_muted(&state.pool, reporter_did.as_str()).await {
        tracing::warn!(
            reporter_did = %reporter_did.as_str(),
            reason_type = %input.reason_type,
            "dropped inbound report from muted reporter",
        );
        return Ok(Json(fabricate_silent_drop_output(&input, &reporter_did)?));
    }

    // Validate the optional free-text reason.
    if let Some(reason) = input.reason.as_deref() {
        if reason.len() > REASON_MAX_BYTES {
            return Err(ApiError::BadRequest("reason exceeds maximum length"));
        }
    }

    // Resolve the subject to a typed shape the find-or-insert
    // pipeline understands. Account-level reports key off `did`;
    // record-level reports key off `uri` and carry the authoring
    // `did` extracted from the AT-URI.
    let resolved = resolve_subject(&input.subject)?;
    let (subject_id, _was_new) = find_or_insert_subject(&state, &resolved).await?;

    // Build the report row. `body` is the free-text reason (empty
    // string when the reporter didn't supply one — the `reports.body`
    // column is NOT NULL).
    let body = input.reason.clone().unwrap_or_default();
    let category = ReportCategory::new(input.reason_type.clone());
    let report = state
        .reports
        .insert(RepoNewReport {
            subject_id: polaris_types::SubjectId(subject_id),
            incident_id: None,
            reporter_did: reporter_did.clone(),
            category,
            body,
        })
        .await?;

    tracing::info!(
        report_id = %report.id.0,
        reporter_did = %reporter_did.as_str(),
        subject_id = %subject_id,
        reason_type = %input.reason_type,
        "inbound createReport accepted",
    );

    // Echo the subject back verbatim — the lexicon contract requires
    // the response to carry the same shape the caller submitted, so
    // the reporter's client can correlate the response to its
    // outstanding request without re-parsing the URI.
    let output = build_output(&input, &report, &reporter_did)?;
    Ok(Json(output))
}

/// Resolve an [`InputSubjectRefs`] variant into a [`ResolvedSubject`]
/// the find-or-insert pipeline understands.
///
/// # Errors
///
/// `ApiError::BadRequest` when:
/// - the subject is the catch-all `Other` variant (unrecognised
///   `$type` discriminator),
/// - the strongRef AT-URI cannot be parsed,
/// - the strongRef AT-URI's authority is not a DID.
fn resolve_subject(subject: &InputSubjectRefs) -> Result<ResolvedSubject, ApiError> {
    match subject {
        InputSubjectRefs::AtprotoAdminDefsRepoRef(repo_ref) => Ok(ResolvedSubject {
            did: Did::new(repo_ref.did.as_str()),
            uri: None,
            kind: SubjectKind::Account,
        }),
        InputSubjectRefs::AtprotoRepoStrongRef(strong_ref) => {
            // `proto_blue_syntax::AtUri` is Display-formatted via
            // its `Display` impl (`at://<authority>/<collection>/<rkey>`);
            // no `as_str()` method. We need an owned String to pass
            // to our find-or-insert pipeline (whose `polaris_types::AtUri`
            // is a `String` newtype with separate identity).
            let uri_str = strong_ref.uri.to_string();
            let authoring_did = extract_did_from_at_uri(uri_str.as_str())
                .ok_or(ApiError::BadRequest("strongRef uri authority is not a DID"))?;
            // Map the AT-URI's collection segment onto Polaris's
            // [`SubjectKind`]: post / list / feed / generator all
            // collapse onto `SubjectKind::Post` for this minimal
            // mapping; finer-grained classification is a follow-up.
            let kind = SubjectKind::Post;
            Ok(ResolvedSubject {
                did: Did::new(authoring_did),
                uri: Some(AtUri::new(&uri_str)),
                kind,
            })
        }
        InputSubjectRefs::Other => Err(ApiError::BadRequest(
            "subject $type not recognised; expected com.atproto.admin.defs#repoRef \
             or com.atproto.repo.strongRef",
        )),
    }
}

/// Extract the authority DID from an AT-URI of the form
/// `at://<did>/<collection>/<rkey>`. Returns `None` on a shape
/// mismatch (missing `at://` prefix, authority is not a `did:`).
fn extract_did_from_at_uri(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("at://")?;
    let authority = rest.split('/').next()?;
    if authority.starts_with("did:") {
        Some(authority)
    } else {
        None
    }
}

/// Build an [`Output`] echo for a SILENTLY-DROPPED report (muted
/// reporter). The response shape is indistinguishable from a real
/// success so the reporter cannot probe for their muted status.
///
/// The fabricated `id` uses the current Unix-millisecond timestamp
/// masked to the i64 non-negative range; this gives a fresh id per
/// drop without persisting any state.
fn fabricate_silent_drop_output(input: &Input, reporter_did: &Did) -> Result<Output, ApiError> {
    let created_at = proto_blue::syntax::Datetime::from_utc(chrono::Utc::now());
    let reported_by = proto_blue::syntax::Did::new(reporter_did.as_str())
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("reporter did invalid: {e}")))?;
    let subject = match &input.subject {
        InputSubjectRefs::AtprotoAdminDefsRepoRef(r) => {
            OutputSubjectRefs::AtprotoAdminDefsRepoRef(r.clone())
        }
        InputSubjectRefs::AtprotoRepoStrongRef(r) => {
            OutputSubjectRefs::AtprotoRepoStrongRef(r.clone())
        }
        InputSubjectRefs::Other => {
            return Err(ApiError::BadRequest("subject $type not recognised"));
        }
    };
    let now_ms = chrono::Utc::now().timestamp_millis().max(0);
    Ok(Output {
        created_at,
        id: now_ms,
        reason: input.reason.clone(),
        reason_type: input.reason_type.clone(),
        reported_by,
        subject,
    })
}

/// Build the [`Output`] echo from the input + the persisted row.
fn build_output(
    input: &Input,
    report: &polaris_types::Report,
    reporter_did: &Did,
) -> Result<Output, ApiError> {
    // Map our internal UUID to a stable i64 id for the wire shape.
    // The Bluesky lexicon spec expects i64; we surface the low 64
    // bits of the UUID (uniformly random for v4), which is opaque
    // to the caller and stable per row.
    let uuid_bytes = report.id.0.as_bytes();
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&uuid_bytes[8..16]);
    let raw = u64::from_be_bytes(buf);
    // Mask the sign bit so the value is always non-negative — i64
    // can represent values up to 2^63 - 1, and the lexicon's id
    // field has no contractual sign requirement but consumers
    // generally expect non-negative. The mask makes the conversion
    // exact (the post-mask value is in [0, 2^63 - 1]).
    let id_i64: i64 = i64::try_from(raw & 0x7FFF_FFFF_FFFF_FFFF).unwrap_or(0);

    let created_at = proto_blue::syntax::Datetime::from_utc(report.created_at);
    let reported_by = proto_blue::syntax::Did::new(reporter_did.as_str())
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("reporter did invalid: {e}")))?;

    // Echo the subject back in the OutputSubjectRefs shape so the
    // caller's client can correlate. The two shapes are structurally
    // identical (Input/Output) but proto-blue generated distinct
    // enum types; we map variant-by-variant.
    let subject = match &input.subject {
        InputSubjectRefs::AtprotoAdminDefsRepoRef(r) => {
            OutputSubjectRefs::AtprotoAdminDefsRepoRef(r.clone())
        }
        InputSubjectRefs::AtprotoRepoStrongRef(r) => {
            OutputSubjectRefs::AtprotoRepoStrongRef(r.clone())
        }
        InputSubjectRefs::Other => {
            // Unreachable in practice — `resolve_subject` rejects
            // the Other variant earlier in the handler. Returned
            // here as a typed error rather than `unreachable!()`
            // to keep the function total.
            return Err(ApiError::BadRequest("subject $type not recognised"));
        }
    };

    Ok(Output {
        created_at,
        id: id_i64,
        reason: input.reason.clone(),
        reason_type: input.reason_type.clone(),
        reported_by,
        subject,
    })
}

/// Extract the reporter DID from the request's `Authorization: Bearer
/// <jwt>` header by decoding the JWT payload and reading the `iss`
/// claim.
///
/// # Signature verification — DEFERRED
///
/// **This function does NOT verify the JWT signature.** A follow-up
/// must fetch the reporter's signing key from PLC and verify the
/// signature before production deployment, otherwise any caller can
/// impersonate any DID. The unverified `iss` is still useful for
/// development + smoke testing where the client is trusted.
///
/// # Errors
///
/// `ApiError::BadRequest` when the header is missing, the bearer
/// token is not a 3-segment JWT, or the payload doesn't decode /
/// doesn't carry an `iss` field. `ApiError::Internal` is never
/// returned here — every internal parse failure surfaces as a 400.
fn extract_reporter_did_unverified(headers: &HeaderMap) -> Result<Did, ApiError> {
    let header_val = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(ApiError::BadRequest("missing Authorization header"))?
        .to_str()
        .map_err(|_| ApiError::BadRequest("Authorization header is not ASCII"))?;
    let token = header_val
        .strip_prefix("Bearer ")
        .ok_or(ApiError::BadRequest(
            "Authorization header must use the Bearer scheme",
        ))?
        .trim();
    let mut segments = token.split('.');
    let _header_segment = segments
        .next()
        .ok_or(ApiError::BadRequest("malformed JWT: missing header"))?;
    let payload_segment = segments
        .next()
        .ok_or(ApiError::BadRequest("malformed JWT: missing payload"))?;
    let _signature_segment = segments
        .next()
        .ok_or(ApiError::BadRequest("malformed JWT: missing signature"))?;
    let payload_bytes = base64_url_decode(payload_segment)
        .ok_or(ApiError::BadRequest("JWT payload is not valid base64url"))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| ApiError::BadRequest("JWT payload is not valid JSON"))?;
    let iss = payload
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .ok_or(ApiError::BadRequest(
            "JWT payload missing iss claim (reporter DID)",
        ))?;
    if !iss.starts_with("did:") {
        return Err(ApiError::BadRequest("JWT iss claim is not a DID"));
    }
    Ok(Did::new(iss))
}

/// Decode a base64url-encoded JWT segment (no padding). Returns
/// `None` on any decode failure.
///
/// JWT spec uses base64url without padding; the `base64` crate's
/// `URL_SAFE_NO_PAD` engine is what matches. We hand-roll the
/// padding-tolerant decode here to avoid pulling in the engine
/// configuration boilerplate for a single call site.
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine.decode(input).ok().or_else(|| {
        // Some clients emit padded base64url; the unpadded engine
        // rejects those. Try the padded variant as a fallback.
        base64::engine::general_purpose::URL_SAFE.decode(input).ok()
    })
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
    use base64::Engine as _;

    #[test]
    fn extract_did_from_at_uri_pulls_authority() {
        assert_eq!(
            extract_did_from_at_uri("at://did:plc:abc/app.bsky.feed.post/3l"),
            Some("did:plc:abc"),
        );
    }

    #[test]
    fn extract_did_from_at_uri_rejects_non_did_authority() {
        assert!(extract_did_from_at_uri("at://example.com/x/y").is_none());
        assert!(extract_did_from_at_uri("https://example.com").is_none());
        assert!(extract_did_from_at_uri("").is_none());
    }

    #[test]
    fn extract_reporter_did_unverified_pulls_iss_claim() {
        // Build a JWT with header `{"alg":"ES256K"}`, payload
        // `{"iss":"did:plc:reporter","exp":9999999999}`, and a
        // dummy signature. We only verify the iss extraction.
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"iss":"did:plc:reporter","exp":9999999999}"#);
        let sig = "dummysig";
        let jwt = format!("{header}.{payload}.{sig}");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {jwt}").parse().unwrap(),
        );
        let did = extract_reporter_did_unverified(&headers).expect("iss extracted");
        assert_eq!(did.as_str(), "did:plc:reporter");
    }

    #[test]
    fn extract_reporter_did_unverified_rejects_missing_header() {
        let headers = HeaderMap::new();
        let err = extract_reporter_did_unverified(&headers).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn extract_reporter_did_unverified_rejects_non_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );
        let err = extract_reporter_did_unverified(&headers).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn extract_reporter_did_unverified_rejects_non_jwt_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer notajwt".parse().unwrap(),
        );
        let err = extract_reporter_did_unverified(&headers).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn extract_reporter_did_unverified_rejects_non_did_iss() {
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"iss":"alice@example.com"}"#);
        let jwt = format!("{header}.{payload}.sig");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {jwt}").parse().unwrap(),
        );
        let err = extract_reporter_did_unverified(&headers).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
