//! `POST /api/setup/*` — server-side helpers driving labeler-record
//! publish + DID-document update using the moderator's session-bound
//! OAuth tokens (issue #85).
//!
//! # Why these endpoints exist
//!
//! The setup wizard (#84) walks a fresh operator through the four
//! steps required to stand up a Polaris labeler:
//!
//! 1. Mint a K-256 signing keypair (the labeler's identity).
//! 2. Publish an `app.bsky.labeler.service` record on the operator's
//!    PDS that declares the labeler's policies + the minted key.
//! 3. Ask the operator's PDS to email a PLC operation challenge
//!    token (the only authentication factor for a PLC operation).
//! 4. Submit the signed PLC operation that adds the
//!    `#atproto_labeler` service entry to the operator's DID document.
//!
//! Each of (2), (3), (4) requires an authenticated XRPC call against
//! the operator's PDS. Rather than re-running the OAuth dance from
//! the wizard's UI, the backend reuses the moderator's existing
//! ATProto OAuth session: the `sessions.refresh_token_enc` column
//! carries a sealed bundle (DPoP keypair JWK + upstream `TokenSet`)
//! that the atproto verifier rebuilds into an `OAuthSession` for
//! each call. This means:
//!
//! - Every call sees the freshest tokens: if a concurrent moderator
//!   request triggered a #66 refresh, the rotated bundle is what
//!   reconstructs the session.
//! - The wizard's UI never has to know about DPoP, PKCE, or PAR.
//! - The browser never holds an OAuth token in JS.
//!
//! # Authorization
//!
//! All four handlers require `Role::Admin`. The first moderator to
//! complete login is granted admin via the #83a first-run path, so
//! the wizard is naturally accessible from the same browser session.
//! A non-admin caller hits a 403; the body is the same opaque
//! `ApiError::Forbidden` payload every other admin-gated endpoint
//! returns so the role boundary is not probeable from a 401 vs. 403
//! shape.
//!
//! # Forbidden patterns observed
//!
//! - No app-password fallback — OAuth only. The wizard is the
//!   moderator's own session; mixing in an app-password code path
//!   would re-introduce the secret-on-disk posture #67 closed.
//! - No `unwrap()` / `expect()` on production paths.
//! - Signing-key bytes never appear in tracing fields or response
//!   bodies. The only public-facing field the handlers emit is the
//!   `did:key:z…` multikey form of the *public* half.

use std::io::Write as _;
use std::path::PathBuf;

use axum::Json;
use axum::extract::{Extension, State};
use proto_blue::api::com::atproto::repo::put_record;
use proto_blue::crypto::{K256Keypair, Keypair as _};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{AnyModeratorAuth, ModeratorAuthCtx, Role};
use crate::config::LabelerSigningKeyConfig;

/// Response from `POST /api/setup/generate-key`.
///
/// Mirrors [`polaris_frontend::api_client::dto::GenerateKeyResponse`].
/// The `did_key` field is the `did:key:z…` multikey form of the
/// freshly-minted public key; the private half is written to the
/// operator-configured path and never appears in the response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyResponse {
    /// `did:key:z…` multikey form of the public key.
    pub did_key: String,
}

/// Request body for `POST /api/setup/publish-labeler-record`.
///
/// Mirrors the frontend DTO of the same name. Field-for-field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishLabelerRecordRequest {
    /// HTTPS URL the labeler's WebSocket subscription endpoint lives at.
    pub service_url: String,
    /// Label values the labeler declares it emits.
    pub label_values: Vec<String>,
}

/// Response from `POST /api/setup/publish-labeler-record`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishLabelerRecordResponse {
    /// `at://<did>/app.bsky.labeler.service/self` AT-URI of the
    /// published record.
    pub at_uri: String,
    /// CID of the committed record.
    pub cid: String,
}

/// Response from `POST /api/setup/request-plc-signature`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPlcSignatureResponse {
    /// Human-readable instruction the wizard surfaces verbatim. The
    /// PDS sends an email to the operator's registered address —
    /// we do not echo the address in the message (privacy).
    pub message: String,
}

/// Request body for `POST /api/setup/submit-plc-operation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPlcOperationRequest {
    /// PLC operation token the operator copy-pasted from email.
    pub token: String,
    /// HTTPS URL the `#atproto_labeler` service entry should point at.
    pub service_url: String,
}

/// Response from `POST /api/setup/submit-plc-operation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPlcOperationResponse {
    /// DID whose document was updated.
    pub did: String,
}

/// Verify the caller is `Role::Admin`, returning `ApiError::Forbidden`
/// otherwise.
fn require_admin(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Borrow the atproto verifier off `ApiState::moderator_auth`, or
/// surface a 400 if the deployment is OIDC-backed (the setup wizard
/// requires the ATProto OAuth surface — there is no DID-document /
/// labeler-record concept under OIDC).
fn atproto_verifier(
    state: &ApiState,
) -> Result<&crate::auth::atproto::AtprotoOauthAuthVerifier, ApiError> {
    let auth = state
        .moderator_auth
        .as_ref()
        .ok_or(ApiError::BadRequest("moderator auth not configured"))?;
    match auth.as_ref() {
        AnyModeratorAuth::Atproto(v) => Ok(v),
        AnyModeratorAuth::Oidc(_) => Err(ApiError::BadRequest(
            "setup wizard requires the atproto OAuth auth backend",
        )),
    }
}

/// `POST /api/setup/generate-key` — mint a fresh K-256 keypair, write
/// the private half to the configured path with mode 0o600, and
/// persist the public DID in `polaris_setup_state`.
///
/// Only the `file-plain` custody mode is supported through this
/// endpoint. Other modes (`passphrase-sealed`, `os-keychain`,
/// `cloud-kms-oracle`) write the key through the `labeler-key-rotate`
/// CLI so the passphrase / keychain prompt / KMS RPC happens with the
/// operator at the terminal — not over an HTTP boundary.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] when the configured signing-key mode
///   is not `file-plain`.
/// - [`ApiError::Conflict`] when the configured path already exists
///   with non-empty content (refusing to overwrite an existing key
///   is part of the safety contract).
/// - [`ApiError::Internal`] on filesystem failure or DB update
///   failure.
pub async fn generate_key(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<GenerateKeyResponse>, ApiError> {
    require_admin(&ctx)?;

    let path = match &state.labeler_signing_key_cfg {
        LabelerSigningKeyConfig::FilePlain { path } => path.clone(),
        LabelerSigningKeyConfig::PassphraseSealed { .. }
        | LabelerSigningKeyConfig::OsKeychain { .. }
        | LabelerSigningKeyConfig::CloudKms { .. } => {
            return Err(ApiError::BadRequest(
                "non-file-plain custody modes use the labeler-key-rotate CLI; see #29 / #30",
            ));
        }
    };

    refuse_existing_key_file(&path)?;
    let (private_hex, did_key) = mint_k256_keypair_hex();
    write_private_key_file(&path, &private_hex)?;

    let path_str = path.display().to_string();
    sqlx::query!(
        r"UPDATE polaris_setup_state
          SET signing_key_path = $1,
              signing_pubkey_did = $2,
              updated_at = now()
          WHERE id = TRUE",
        path_str,
        did_key,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(Json(GenerateKeyResponse { did_key }))
}

/// Mint a fresh K-256 keypair and return the hex-encoded private
/// scalar plus the `did:key:z…` form of the public half.
fn mint_k256_keypair_hex() -> (String, String) {
    use proto_blue::crypto::ExportableKeypair as _;
    let kp = K256Keypair::generate();
    let private = kp.export_private_key();
    let did = kp.did();
    (hex::encode(private), did)
}

/// Refuse to overwrite an existing non-empty key file.
fn refuse_existing_key_file(path: &std::path::Path) -> Result<(), ApiError> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() && meta.len() > 0 => Err(ApiError::Conflict(
            "labeler signing-key file already exists at the configured path",
        )),
        // File does not exist (or exists but is empty) — both are
        // accepted, the write will overwrite the empty placeholder
        // the operator may have created to set permissions.
        Ok(_) | Err(_) => Ok(()),
    }
}

/// Write the hex-encoded private key to `path` with mode 0o600.
///
/// On non-Unix platforms (Windows, wasm) the mode cannot be set
/// through `OpenOptionsExt`; the file is still created but a startup
/// WARN is logged. The labeler-profile deployment target is Linux
/// servers so the Unix path is the production hot path.
fn write_private_key_file(path: &std::path::Path, hex_str: &str) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ApiError::Internal(anyhow::anyhow!(
                    "failed to create parent directory for signing-key file: {e}"
                ))
            })?;
        }
    }

    let mut file = open_private_key_file(path)?;
    file.write_all(hex_str.as_bytes()).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to write signing-key bytes to disk: {e}"
        ))
    })?;
    file.write_all(b"\n").map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to write trailing newline to signing-key file: {e}"
        ))
    })?;
    file.sync_all().map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to fsync signing-key file after write: {e}"
        ))
    })?;
    Ok(())
}

#[cfg(unix)]
fn open_private_key_file(path: &std::path::Path) -> Result<std::fs::File, ApiError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to create signing-key file with mode 0o600: {e}"
            ))
        })
}

#[cfg(not(unix))]
fn open_private_key_file(path: &std::path::Path) -> Result<std::fs::File, ApiError> {
    tracing::warn!(
        path = %path.display(),
        "signing-key file written on non-Unix host; cannot enforce mode 0o600"
    );
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("failed to create signing-key file: {e}")))
}

/// `POST /api/setup/publish-labeler-record` — build the
/// `app.bsky.labeler.service` record and POST it through the
/// moderator's OAuth session.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] — non-admin caller.
/// - [`ApiError::BadRequest`] — `signing_pubkey_did` not yet set in
///   `polaris_setup_state` (the operator skipped the generate-key
///   step), the build helpers rejected the inputs, or the OAuth
///   backend is not atproto.
/// - [`ApiError::Internal`] — DB failure, PDS rejection, malformed
///   PDS response.
pub async fn publish_labeler_record(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(req): Json<PublishLabelerRecordRequest>,
) -> Result<Json<PublishLabelerRecordResponse>, ApiError> {
    require_admin(&ctx)?;

    let signing_pubkey_did = load_signing_pubkey_did(&state).await?;

    // Build + validate the record using the shared library code so
    // the wizard and the CLI emit identical wire shapes.
    let record =
        polaris_publish_labeler_record::build_labeler_service_record(
            &req.service_url,
            &signing_pubkey_did,
            req.label_values,
        )
        .map_err(|e| {
            tracing::warn!(error = %e, "labeler service record build rejected by polaris-publish-labeler-record");
            ApiError::BadRequest("labeler service record build failed; check service URL + label values")
        })?;
    polaris_publish_labeler_record::validate_record(&record).map_err(|e| {
        tracing::warn!(error = %e, "labeler service record failed lexicon validation");
        ApiError::Internal(anyhow::anyhow!(
            "labeler service record failed lexicon validation"
        ))
    })?;

    let verifier = atproto_verifier(&state)?;
    let oauth_ctx = verifier
        .build_oauth_session_for_moderator(ctx.moderator_id)
        .await
        .map_err(|e| map_oauth_setup_error(&e))?;

    let record_json = record.to_json().map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "serialising labeler service record to JSON: {e}"
        ))
    })?;

    let put_input = build_put_record_input(&oauth_ctx.did, record_json)?;
    let put_input_value = serde_json::to_value(&put_input).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "serialising put_record::Input to JSON: {e}"
        ))
    })?;

    let endpoint = format!("{}/xrpc/com.atproto.repo.putRecord", oauth_ctx.pds_url);
    let response = oauth_ctx
        .session
        .post(&endpoint, &put_input_value)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "putRecord OAuth POST failed");
            ApiError::Internal(anyhow::anyhow!("putRecord OAuth POST failed"))
        })?;
    if !response.is_success() {
        tracing::warn!(
            status = response.status,
            body = %String::from_utf8_lossy(&response.body),
            "putRecord returned non-2xx"
        );
        return Err(ApiError::Internal(anyhow::anyhow!(
            "putRecord returned HTTP {}",
            response.status
        )));
    }

    let output: put_record::Output = serde_json::from_slice(&response.body).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "decoding putRecord response JSON failed: {e}"
        ))
    })?;
    let at_uri = output.uri.to_string();
    let cid = output.cid;

    sqlx::query!(
        r"UPDATE polaris_setup_state
          SET labeler_record_uri = $1,
              updated_at = now()
          WHERE id = TRUE",
        &at_uri,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(Json(PublishLabelerRecordResponse { at_uri, cid }))
}

/// `POST /api/setup/request-plc-signature` — ask the moderator's
/// PDS to email a PLC operation challenge token.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] — non-admin caller.
/// - [`ApiError::BadRequest`] — OAuth backend not atproto.
/// - [`ApiError::Internal`] — PDS rejected the request.
pub async fn request_plc_signature(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<RequestPlcSignatureResponse>, ApiError> {
    require_admin(&ctx)?;

    let verifier = atproto_verifier(&state)?;
    let oauth_ctx = verifier
        .build_oauth_session_for_moderator(ctx.moderator_id)
        .await
        .map_err(|e| map_oauth_setup_error(&e))?;

    // The lexicon for `requestPlcOperationSignature` declares no
    // input. proto-blue's OAuthSession::post always writes a JSON
    // body so we send `{}` — matches what the CLI in
    // polaris-publish-did-service does.
    let empty = serde_json::Value::Object(serde_json::Map::new());
    let endpoint = format!(
        "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
        oauth_ctx.pds_url
    );
    let response = oauth_ctx
        .session
        .post(&endpoint, &empty)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "requestPlcOperationSignature OAuth POST failed");
            ApiError::Internal(anyhow::anyhow!(
                "requestPlcOperationSignature OAuth POST failed"
            ))
        })?;
    if !response.is_success() {
        tracing::warn!(
            status = response.status,
            body = %String::from_utf8_lossy(&response.body),
            "requestPlcOperationSignature returned non-2xx"
        );
        return Err(ApiError::Internal(anyhow::anyhow!(
            "requestPlcOperationSignature returned HTTP {}",
            response.status
        )));
    }

    Ok(Json(RequestPlcSignatureResponse {
        message: "Check your email for the PLC operation token. The email comes from your PDS."
            .to_owned(),
    }))
}

/// `POST /api/setup/submit-plc-operation` — sign and submit the PLC
/// operation that adds the `#atproto_labeler` service entry to the
/// moderator's DID document.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] — non-admin caller.
/// - [`ApiError::BadRequest`] — `signing_pubkey_did` missing,
///   moderator-row lookup failed, or document build rejected the
///   inputs.
/// - [`ApiError::Internal`] — PDS / PLC-directory rejection,
///   malformed response, or DB update failure.
#[allow(
    clippy::too_many_lines,
    reason = "5-step PLC flow (lookup → build payloads → sign → submit → persist) reads more clearly as one linear function than a chain of micro-helpers"
)]
pub async fn submit_plc_operation(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(req): Json<SubmitPlcOperationRequest>,
) -> Result<Json<SubmitPlcOperationResponse>, ApiError> {
    require_admin(&ctx)?;

    let signing_pubkey_did = load_signing_pubkey_did(&state).await?;

    let verifier = atproto_verifier(&state)?;
    let oauth_ctx = verifier
        .build_oauth_session_for_moderator(ctx.moderator_id)
        .await
        .map_err(|e| map_oauth_setup_error(&e))?;

    // Look up the moderator's handle for the did:web id derivation.
    // The handle is the value the OAuth complete-login path wrote
    // into `moderators.display_name` (see
    // `upsert_atproto_moderator_in_tx`).
    let handle = sqlx::query_scalar!(
        r"SELECT display_name FROM moderators WHERE id = $1",
        ctx.moderator_id.0,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?
    .flatten()
    .ok_or(ApiError::BadRequest(
        "moderator row has no handle on file; re-login with --atproto",
    ))?;

    // Build the target DID document so we can extract the
    // `service` + `verificationMethod` payloads for the PLC sign
    // call. Re-uses the same library function the CLI uses; the
    // wire shape is therefore identical.
    let target_doc = polaris_publish_did_service::build_did_web_document(
        &handle,
        &oauth_ctx.pds_url,
        &signing_pubkey_did,
        &req.service_url,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "build_did_web_document rejected setup inputs");
        ApiError::BadRequest("DID document build failed; check service URL + signing key")
    })?;

    let services_payload = polaris_publish_did_service::build_plc_services_payload(&target_doc)
        .ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!(
                "internal: built DID document missing service array"
            ))
        })?;
    let verification_methods_payload =
        polaris_publish_did_service::build_plc_verification_methods_payload(&target_doc)
            .ok_or_else(|| {
                ApiError::Internal(anyhow::anyhow!(
                    "internal: built DID document missing verificationMethod array"
                ))
            })?;

    // Sign the PLC operation. The lexicon declares an `Input` with
    // `token` + optional services/verificationMethods/rotationKeys/
    // alsoKnownAs; we leave the rotation keys + alsoKnownAs to the
    // PDS's existing values (passing `None` preserves them) so the
    // labeler-service entry is an additive update.
    let sign_body = serde_json::json!({
        "token": req.token,
        "services": services_payload,
        "verificationMethods": verification_methods_payload,
    });
    let sign_endpoint = format!(
        "{}/xrpc/com.atproto.identity.signPlcOperation",
        oauth_ctx.pds_url
    );
    let sign_response = oauth_ctx
        .session
        .post(&sign_endpoint, &sign_body)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "signPlcOperation OAuth POST failed");
            ApiError::Internal(anyhow::anyhow!("signPlcOperation OAuth POST failed"))
        })?;
    if !sign_response.is_success() {
        tracing::warn!(
            status = sign_response.status,
            body = %String::from_utf8_lossy(&sign_response.body),
            "signPlcOperation returned non-2xx"
        );
        return Err(ApiError::Internal(anyhow::anyhow!(
            "signPlcOperation returned HTTP {}",
            sign_response.status
        )));
    }
    let signed_value: serde_json::Value =
        serde_json::from_slice(&sign_response.body).map_err(|e| {
            ApiError::Internal(anyhow::anyhow!(
                "decoding signPlcOperation response JSON failed: {e}"
            ))
        })?;
    let operation = signed_value.get("operation").cloned().ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!(
            "signPlcOperation response missing `operation` field"
        ))
    })?;

    // Submit the signed operation.
    let submit_body = serde_json::json!({ "operation": operation });
    let submit_endpoint = format!(
        "{}/xrpc/com.atproto.identity.submitPlcOperation",
        oauth_ctx.pds_url
    );
    let submit_response = oauth_ctx
        .session
        .post(&submit_endpoint, &submit_body)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "submitPlcOperation OAuth POST failed");
            ApiError::Internal(anyhow::anyhow!("submitPlcOperation OAuth POST failed"))
        })?;
    if !submit_response.is_success() {
        tracing::warn!(
            status = submit_response.status,
            body = %String::from_utf8_lossy(&submit_response.body),
            "submitPlcOperation returned non-2xx"
        );
        return Err(ApiError::Internal(anyhow::anyhow!(
            "submitPlcOperation returned HTTP {}",
            submit_response.status
        )));
    }

    sqlx::query!(
        r"UPDATE polaris_setup_state
          SET did_document_updated_at = now(),
              updated_at = now()
          WHERE id = TRUE",
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(Json(SubmitPlcOperationResponse { did: oauth_ctx.did }))
}

/// Build the `put_record::Input` for the labeler service record.
///
/// The lexicon types (`Nsid`, `AtIdentifier`, `RecordKey`) validate
/// each component so a malformed account / collection / rkey
/// surfaces as `ApiError::BadRequest` here rather than getting sent
/// to the PDS as a malformed XRPC call.
fn build_put_record_input(
    account: &str,
    record_json: serde_json::Value,
) -> Result<put_record::Input, ApiError> {
    let collection = proto_blue::syntax::Nsid::new(
        polaris_publish_labeler_record::RECORD_COLLECTION,
    )
    .map_err(|_| {
        ApiError::Internal(anyhow::anyhow!(
            "internal: RECORD_COLLECTION constant is not a valid NSID"
        ))
    })?;
    let repo = proto_blue::syntax::AtIdentifier::new(account).map_err(|_| {
        ApiError::BadRequest("moderator account is not a valid handle or DID for put_record")
    })?;
    let rkey = proto_blue::syntax::RecordKey::new(polaris_publish_labeler_record::RECORD_RKEY)
        .map_err(|_| {
            ApiError::Internal(anyhow::anyhow!(
                "internal: RECORD_RKEY constant is not a valid record key"
            ))
        })?;

    Ok(put_record::Input {
        collection,
        record: record_json,
        repo,
        rkey,
        swap_commit: None,
        swap_record: None,
        validate: Some(true),
    })
}

/// Read `polaris_setup_state.signing_pubkey_did` and surface a 400
/// when it's missing — the wizard requires the generate-key step
/// to run first.
async fn load_signing_pubkey_did(state: &ApiState) -> Result<String, ApiError> {
    let row = sqlx::query!(r"SELECT signing_pubkey_did FROM polaris_setup_state WHERE id = TRUE",)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;
    row.signing_pubkey_did.ok_or(ApiError::BadRequest(
        "signing key not yet generated; call /api/setup/generate-key first",
    ))
}

/// Map a `build_oauth_session_for_moderator` error to an
/// `ApiError`. The opaque mapping is deliberate: every
/// auth-side variant (session not found, crypto failure, JWK
/// shape mismatch) surfaces as a generic 500 so the wire
/// shape does not leak why the per-moderator OAuth session
/// is unusable.
fn map_oauth_setup_error(err: &crate::auth::AuthError) -> ApiError {
    tracing::warn!(error = %err, "setup endpoint failed to rebuild moderator OAuth session");
    match err {
        crate::auth::AuthError::SessionNotFound => ApiError::BadRequest(
            "no active moderator session bound to this account; re-login required",
        ),
        _ => ApiError::Internal(anyhow::anyhow!(
            "moderator OAuth session could not be reconstructed"
        )),
    }
}

// Silence "unused import" if PathBuf doesn't appear in a slimmer
// future refactor — it's load-bearing for `LabelerSigningKeyConfig`
// field types but the compiler does not see that through the match
// arm.
#[allow(dead_code, reason = "keeps PathBuf import alive for future helpers")]
const _PHANTOM_PATH: Option<PathBuf> = None;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::auth::ModeratorId;

    fn ctx_with(roles: &[Role]) -> ModeratorAuthCtx {
        ModeratorAuthCtx::new(ModeratorId::new_v4(), roles.iter().copied().collect())
    }

    #[test]
    fn require_admin_accepts_admin_role() {
        let ctx = ctx_with(&[Role::Admin]);
        require_admin(&ctx).expect("admin must pass");
    }

    #[test]
    fn require_admin_rejects_non_admin_roles() {
        for role in [
            Role::SeniorModerator,
            Role::Moderator,
            Role::Triage,
            Role::ReadOnly,
        ] {
            let ctx = ctx_with(&[role]);
            let err = require_admin(&ctx).expect_err("non-admin must be rejected");
            assert!(
                matches!(err, ApiError::Forbidden),
                "expected Forbidden, got {err:?}",
            );
        }
    }

    #[test]
    fn require_admin_rejects_empty_role_set() {
        let ctx = ModeratorAuthCtx::new(ModeratorId::new_v4(), HashSet::new());
        let err = require_admin(&ctx).expect_err("empty role set must be rejected");
        assert!(matches!(err, ApiError::Forbidden), "got {err:?}");
    }

    #[test]
    fn mint_k256_keypair_hex_returns_64_hex_chars_and_did_key_z_prefix() {
        let (hex_priv, did) = mint_k256_keypair_hex();
        assert_eq!(
            hex_priv.len(),
            64,
            "K-256 private scalar must be 32 bytes (64 hex chars)"
        );
        assert!(
            hex_priv.chars().all(|c| c.is_ascii_hexdigit()),
            "private hex must be ASCII hex"
        );
        assert!(
            did.starts_with("did:key:z"),
            "did:key must use the z-multibase prefix, got {did}"
        );
    }

    #[test]
    fn build_put_record_input_rejects_invalid_handle() {
        let err = build_put_record_input(
            "not a valid handle at all spaces inside",
            serde_json::json!({}),
        )
        .expect_err("invalid handle must surface as BadRequest");
        assert!(matches!(err, ApiError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn refuse_existing_key_file_accepts_missing_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.key");
        refuse_existing_key_file(&path).expect("missing path is fine");
    }

    #[test]
    fn refuse_existing_key_file_rejects_existing_nonempty_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), "existing-content").unwrap();
        let err =
            refuse_existing_key_file(tmp.path()).expect_err("existing non-empty file must reject");
        assert!(matches!(err, ApiError::Conflict(_)), "got {err:?}");
    }
}
