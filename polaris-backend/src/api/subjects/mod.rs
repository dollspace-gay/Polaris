//! `POST /api/subjects/lookup` — command-palette subject lookup (issue #92).
//!
//! Given a moderator-supplied identifier (DID, AT-URI, bsky.app URL, or
//! bare handle), this endpoint:
//!
//! 1. Parses the identifier into a typed [`parse::ParsedIdentifier`].
//! 2. Resolves the identifier to a canonical (DID, optional AT-URI,
//!    kind) triple. Handle resolution uses the atproto verifier's
//!    bound [`proto_blue::identity::IdResolver`] — the same resolver
//!    that drove the login flow. No parallel HTTP resolver path.
//! 3. Looks up the existing `subjects` row by DID (for accounts) or
//!    AT-URI (for posts). If present, returns the existing
//!    `subject_id`. If absent, INSERTs a new row.
//!
//! # Idempotency
//!
//! The handler is **read-then-insert**:
//!
//! - Look up `subjects` by `did` / `uri` first.
//! - If found, return the existing `subject_id` (no INSERT).
//! - If not found, INSERT a new row and return the new id.
//!
//! Two concurrent lookups for the same DID race on the INSERT. The
//! `subjects_account_did_uniq` partial unique index in migration 16
//! rejects the loser with `RepoError::UniqueViolation`; we
//! catch-and-re-read so both callers see the same `subject_id`.
//! Posts (no DB-level unique constraint on `uri`) can produce two rows
//! under a hostile race; the operator-visible cost is one duplicated
//! `subjects` row, not a wedged handler. The next lookup converges:
//! both rows will be reported by `get_by_uri`, but only the first one
//! `LIMIT 1` picks is returned, and the second row becomes orphan
//! garbage with no incidents/actions attached to it.
//!
//! # Authorization
//!
//! Admin OR moderator role required. Triage and read-only roles
//! cannot use the command palette to discover new subjects (the
//! create-on-miss path is a soft form of side-effect: it stamps the
//! `first_seen_by_mod` timestamp). Per Workstream A's
//! `submit_action` pattern, the role check happens before any work.
//!
//! # Metrics
//!
//! Increments `polaris_subject_lookups_total{result}` once per call;
//! `result` is one of `created`, `existing`, `unresolvable`,
//! `malformed`. The label set is fixed at four values.
//!
//! # Forbidden patterns observed
//!
//! - No `unwrap()` / `expect()` on the production path. Every fallible
//!   step propagates through `?` into the typed [`ApiError`] variants.
//! - No regex for URL parsing — `url::Url::parse` via the
//!   [`parse::parse_identifier`] pure function.
//! - No mock for handle resolution in production code — the
//!   `identity_resolver` field on [`AtprotoOauthAuthVerifier`] is the
//!   single resolver path. Tests intercept at the HTTP
//!   [`proto_blue::common::fetch::FetchHandler`] boundary.

pub mod parse;

use axum::Json;
use axum::extract::{Extension, State};
use chrono::Utc;
use polaris_types::{AtUri, Did, SubjectKind};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::atproto::AtprotoOauthAuthVerifier;
use crate::auth::{AnyModeratorAuth, ModeratorAuthCtx, Role};
use crate::repo::RepoError;
use crate::repo::subject::{NewSubject, SubjectRepo};

use parse::{ParsedIdentifier, build_at_uri, identity_is_did, parse_identifier};

/// Wire shape of the request body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubjectLookupRequest {
    /// The moderator-pasted identifier (DID, AT-URI, bsky.app URL, or
    /// bare handle). Validated server-side via
    /// [`parse::parse_identifier`]; the granular parse-error variants
    /// fold into `400 malformed_identifier`.
    pub identifier: String,
}

/// Wire shape of the success response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubjectLookupResponse {
    /// Stable Polaris `subjects.id` as the canonical hyphenated UUID.
    pub subject_id: String,
    /// Resolved DID. Always populated — even post-kind subjects carry
    /// the authoring DID (decoded from the AT-URI authority).
    pub did: String,
    /// Canonical AT-URI when `kind == "post"`; `None` for accounts.
    pub uri: Option<String>,
    /// `"account"` or `"post"`. Mirrors `SubjectKind::as_str` so the
    /// frontend's branch logic matches the existing case-view DTO
    /// shape.
    pub kind: String,
}

/// Result categorisation for the
/// `polaris_subject_lookups_total{result}` Prometheus counter.
#[derive(Debug, Clone, Copy)]
enum LookupResult {
    /// New `subjects` row was inserted.
    Created,
    /// Existing `subjects` row was returned.
    Existing,
    /// Handle / DID resolution failed (404 `identifier_unresolvable`).
    Unresolvable,
    /// Parser rejected the input (400 `malformed_identifier`).
    Malformed,
}

impl LookupResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Existing => "existing",
            Self::Unresolvable => "unresolvable",
            Self::Malformed => "malformed",
        }
    }
}

/// Increment the `polaris_subject_lookups_total{result}` counter.
fn record_lookup_result(result: LookupResult) {
    metrics::counter!(
        "polaris_subject_lookups_total",
        "result" => result.as_str(),
    )
    .increment(1);
}

/// Verify the caller carries either `Role::Admin` or `Role::Moderator`.
///
/// Triage / read-only roles cannot use the palette: the create-on-miss
/// path mutates state. Senior-moderator inherits the check via the
/// match (senior moderators may also moderate, so the check is
/// inclusive — they pass if either role is in the set).
fn require_admin_or_moderator(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin)
        || ctx.roles.contains(&Role::SeniorModerator)
        || ctx.roles.contains(&Role::Moderator)
    {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Borrow the atproto verifier off `ApiState::moderator_auth`, or
/// surface a 400 if the deployment is OIDC-backed (the command
/// palette requires the ATProto handle / DID resolver — there is no
/// equivalent under OIDC).
fn atproto_verifier(state: &ApiState) -> Result<&AtprotoOauthAuthVerifier, ApiError> {
    let auth = state
        .moderator_auth
        .as_ref()
        .ok_or(ApiError::BadRequest("moderator auth not configured"))?;
    match auth.as_ref() {
        AnyModeratorAuth::Atproto(v) => Ok(v),
        AnyModeratorAuth::Oidc(_) => Err(ApiError::BadRequest(
            "subject lookup requires the atproto auth backend",
        )),
    }
}

/// Resolved-identifier shape the handler hands to the read-then-insert
/// path. The fields are typed (`Did` / `AtUri` / `SubjectKind`) so the
/// SQL-bound code never re-parses a string.
///
/// `pub(crate)` so the inbound `com.atproto.moderation.createReport`
/// handler (`crate::api::moderation::create_report`) can reuse the
/// same find-or-insert pipeline when materialising the report's
/// subject row.
pub(crate) struct ResolvedSubject {
    pub(crate) did: Did,
    pub(crate) uri: Option<AtUri>,
    pub(crate) kind: SubjectKind,
}

/// Internal outcome type. Carries the `LookupResult` label alongside
/// the success/failure shape so the handler boundary can emit a
/// single metric increment per call without re-classifying error
/// variants by string matching.
enum LookupOutcome {
    Hit(SubjectLookupResponse, LookupResult),
    Err(ApiError, Option<LookupResult>),
}

/// Axum handler for `POST /api/subjects/lookup`.
///
/// The handler is the thin shell over [`lookup_inner`]; the inner fn
/// returns [`LookupOutcome`] so the metric increment at the boundary
/// is exhaustive (one increment per call when the outcome matches one
/// of the four counter discriminators, silent for the auth /
/// backend-misconfiguration paths).
#[allow(
    clippy::missing_errors_doc,
    reason = "handler-level errors documented on ApiError variants"
)]
#[tracing::instrument(
    name = "subjects.lookup",
    skip(state, ctx, req),
    fields(
        moderator_id = %ctx.moderator_id.0,
        identifier_len = req.identifier.len(),
    ),
)]
pub async fn lookup(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(req): Json<SubjectLookupRequest>,
) -> Result<Json<SubjectLookupResponse>, ApiError> {
    tracing::info!("subject lookup received");
    let outcome = lookup_inner(&state, &ctx, &req.identifier).await;
    match outcome {
        LookupOutcome::Hit(response, result) => {
            tracing::info!(
                subject_id = %response.subject_id,
                did = %response.did,
                kind = %response.kind,
                outcome = ?result,
                "subject lookup resolved",
            );
            record_lookup_result(result);
            Ok(Json(response))
        }
        LookupOutcome::Err(err, Some(result)) => {
            tracing::warn!(error = %err, outcome = ?result, "subject lookup failed");
            record_lookup_result(result);
            Err(err)
        }
        LookupOutcome::Err(err, None) => {
            tracing::warn!(error = %err, "subject lookup rejected before resolver");
            Err(err)
        }
    }
}

/// Inner lookup flow. Wraps the success / failure shape in the typed
/// [`LookupOutcome`] discriminator so the handler boundary's metric
/// emission is exhaustive.
async fn lookup_inner(state: &ApiState, ctx: &ModeratorAuthCtx, identifier: &str) -> LookupOutcome {
    if let Err(err) = require_admin_or_moderator(ctx) {
        return LookupOutcome::Err(err, None);
    }

    let parsed = match parse_identifier(identifier) {
        Ok(p) => p,
        Err(_e) => {
            tracing::debug!(
                identifier_len = identifier.len(),
                "subject lookup rejected: malformed identifier",
            );
            return LookupOutcome::Err(
                ApiError::BadRequest("malformed_identifier"),
                Some(LookupResult::Malformed),
            );
        }
    };

    let verifier = match atproto_verifier(state) {
        Ok(v) => v,
        Err(err) => return LookupOutcome::Err(err, None),
    };

    let resolved = match resolve_identifier(verifier, parsed).await {
        Ok(r) => r,
        Err(ApiError::NotFound) => {
            return LookupOutcome::Err(ApiError::NotFound, Some(LookupResult::Unresolvable));
        }
        Err(err) => return LookupOutcome::Err(err, None),
    };

    match find_or_insert_subject(state, &resolved).await {
        Ok((subject_id, created)) => {
            let response = SubjectLookupResponse {
                subject_id: subject_id.to_string(),
                did: resolved.did.0,
                uri: resolved.uri.map(|u| u.0),
                kind: resolved.kind.as_str().to_owned(),
            };
            let result = if created {
                LookupResult::Created
            } else {
                LookupResult::Existing
            };
            LookupOutcome::Hit(response, result)
        }
        Err(err) => LookupOutcome::Err(err, None),
    }
}

/// Resolve a parsed identifier to a typed `(did, uri, kind)` triple.
///
/// The handle-bearing variants drive the verifier's
/// [`proto_blue::identity::IdResolver`] to convert the handle to a
/// DID. The DID-bearing variants short-circuit; no resolution call.
///
/// # Errors
///
/// - [`ApiError::NotFound`] when handle resolution fails (the handle
///   has no DNS / HTTPS DID binding, or the DID does not claim the
///   handle in its `alsoKnownAs`). Mapped to `404
///   identifier_unresolvable` at the wire.
async fn resolve_identifier(
    verifier: &AtprotoOauthAuthVerifier,
    parsed: ParsedIdentifier,
) -> Result<ResolvedSubject, ApiError> {
    match parsed {
        ParsedIdentifier::Did { did } => Ok(ResolvedSubject {
            did: Did::new(did),
            uri: None,
            kind: SubjectKind::Account,
        }),
        ParsedIdentifier::AtUriWithDid {
            did,
            collection,
            rkey,
        } => {
            let uri = rkey
                .as_ref()
                .map(|rk| AtUri::new(build_at_uri(&did, &collection, rk)));
            Ok(ResolvedSubject {
                did: Did::new(did),
                uri,
                kind: SubjectKind::Post,
            })
        }
        ParsedIdentifier::AtUriWithHandle {
            handle,
            collection,
            rkey,
        } => {
            let did = resolve_handle_to_did(verifier, &handle).await?;
            let uri = rkey
                .as_ref()
                .map(|rk| AtUri::new(build_at_uri(&did, &collection, rk)));
            Ok(ResolvedSubject {
                did: Did::new(did),
                uri,
                kind: SubjectKind::Post,
            })
        }
        ParsedIdentifier::BskyAppProfile { who, post_rkey } => {
            let did = if identity_is_did(&who) {
                who.clone()
            } else {
                resolve_handle_to_did(verifier, &who).await?
            };
            let (uri, kind) = match post_rkey {
                Some(rk) => (
                    Some(AtUri::new(build_at_uri(&did, "app.bsky.feed.post", &rk))),
                    SubjectKind::Post,
                ),
                None => (None, SubjectKind::Account),
            };
            Ok(ResolvedSubject {
                did: Did::new(did),
                uri,
                kind,
            })
        }
        ParsedIdentifier::BareHandle { handle } => {
            let did = resolve_handle_to_did(verifier, &handle).await?;
            Ok(ResolvedSubject {
                did: Did::new(did),
                uri: None,
                kind: SubjectKind::Account,
            })
        }
    }
}

/// Resolve a handle to a DID via the verifier's bound [`IdResolver`].
///
/// We deliberately use `handle.resolve(...)` (not
/// `resolve_handle_verified`) here. The verified flavour additionally
/// asserts the DID document's `alsoKnownAs` mentions the handle — a
/// good check at login time but too strict for ad-hoc lookup: a
/// moderator pasting a handle that's been recently rebound should
/// still be able to land on the subject, and the case page is what
/// surfaces "this handle is stale" via the live profile fetch.
///
/// `Ok(None)` from the resolver collapses to
/// [`ApiError::NotFound`]; the wire layer maps that to `404
/// identifier_unresolvable`.
///
/// [`IdResolver`]: proto_blue::identity::IdResolver
async fn resolve_handle_to_did(
    verifier: &AtprotoOauthAuthVerifier,
    handle: &str,
) -> Result<String, ApiError> {
    let did_opt = verifier
        .identity_resolver()
        .handle
        .resolve(handle)
        .await
        .map_err(|err| {
            tracing::warn!(
                handle,
                error = %err,
                "handle resolution failed for subject lookup",
            );
            ApiError::NotFound
        })?;
    did_opt.ok_or_else(|| {
        tracing::debug!(handle, "handle resolution returned no DID");
        ApiError::NotFound
    })
}

/// Read-then-insert. Returns `(subject_id, created_flag)`.
///
/// Strategy:
///
/// 1. Try `get_by_did` (always — even posts carry the authoring DID).
/// 2. For posts with a URI, additionally try `get_by_uri` if step 1
///    missed (a different account-kind row could exist for the same
///    DID; the URI lookup is the canonical de-dup for the post).
/// 3. If both miss, INSERT.
/// 4. On a UNIQUE-constraint violation during INSERT, re-read and
///    return the now-extant row.
pub(crate) async fn find_or_insert_subject(
    state: &ApiState,
    resolved: &ResolvedSubject,
) -> Result<(uuid::Uuid, bool), ApiError> {
    // Step 1: post-kind subjects are keyed by URI first. The DID may
    // overlap with the authoring account's row; we want the POST row.
    if let Some(uri) = &resolved.uri {
        if let Some(existing) = state.subjects.get_by_uri(uri).await? {
            return Ok((existing.id.0, false));
        }
    } else if let Some(existing) = state.subjects.get_by_did(&resolved.did).await? {
        // Step 2: account-kind subjects key off DID.
        return Ok((existing.id.0, false));
    }

    // Step 3: INSERT.
    let new = NewSubject {
        kind: resolved.kind,
        did: Some(resolved.did.clone()),
        uri: resolved.uri.clone(),
        created_at: Utc::now(),
    };
    match state.subjects.insert(new).await {
        Ok(subject) => Ok((subject.id.0, true)),
        // Step 4: race-loser path. Another concurrent lookup beat us
        // to the INSERT and the partial unique index on
        // `subjects(did) WHERE kind = 'account' AND did IS NOT NULL`
        // rejected our row. Re-read to return the winning row's id.
        Err(RepoError::UniqueViolation(_)) => {
            if let Some(uri) = &resolved.uri {
                if let Some(existing) = state.subjects.get_by_uri(uri).await? {
                    return Ok((existing.id.0, false));
                }
            }
            if let Some(existing) = state.subjects.get_by_did(&resolved.did).await? {
                return Ok((existing.id.0, false));
            }
            // No row visible even though INSERT failed unique. This
            // shouldn't happen — the unique violation implies a row
            // exists. Surface as the original error for the operator
            // to investigate.
            Err(ApiError::Conflict(
                "subject lookup race left no visible row",
            ))
        }
        Err(other) => Err(ApiError::from(other)),
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
    use std::collections::HashSet;

    use crate::auth::ModeratorId;

    fn ctx_with(roles: &[Role]) -> ModeratorAuthCtx {
        let mut set = HashSet::new();
        for r in roles {
            set.insert(*r);
        }
        ModeratorAuthCtx::new(ModeratorId(uuid::Uuid::new_v4()), set)
    }

    #[test]
    fn require_admin_or_moderator_accepts_admin() {
        require_admin_or_moderator(&ctx_with(&[Role::Admin])).unwrap();
    }

    #[test]
    fn require_admin_or_moderator_accepts_moderator() {
        require_admin_or_moderator(&ctx_with(&[Role::Moderator])).unwrap();
    }

    #[test]
    fn require_admin_or_moderator_accepts_senior_moderator() {
        require_admin_or_moderator(&ctx_with(&[Role::SeniorModerator])).unwrap();
    }

    #[test]
    fn require_admin_or_moderator_rejects_triage_and_read_only() {
        for role in [Role::Triage, Role::ReadOnly] {
            let err = require_admin_or_moderator(&ctx_with(&[role])).unwrap_err();
            assert!(matches!(err, ApiError::Forbidden));
        }
    }

    #[test]
    fn require_admin_or_moderator_rejects_empty_role_set() {
        let err = require_admin_or_moderator(&ctx_with(&[])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn lookup_result_strings_are_stable() {
        assert_eq!(LookupResult::Created.as_str(), "created");
        assert_eq!(LookupResult::Existing.as_str(), "existing");
        assert_eq!(LookupResult::Unresolvable.as_str(), "unresolvable");
        assert_eq!(LookupResult::Malformed.as_str(), "malformed");
    }
}
