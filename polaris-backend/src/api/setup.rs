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
use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, State};
use proto_blue::api::com::atproto::repo::put_record;
use proto_blue::crypto::{K256Keypair, Keypair as _};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{AnyModeratorAuth, ModeratorAuthCtx, Role};
use crate::config::LabelerSigningKeyConfig;
use crate::labeler::signer::SigningKey;
use crate::labeler::signer::file_plain::FilePlainSigner;

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
    /// `true` when the configured key file already held a valid
    /// K-256 secret and the handler adopted it instead of writing a
    /// fresh key. This lets the wizard render "Existing signing key
    /// detected" rather than "Generated signing key" so the operator
    /// is not misled. `false` for the freshly-minted path.
    #[serde(default)]
    pub already_provisioned: bool,
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

/// `POST /api/setup/generate-key` — provision the labeler's K-256
/// signing key at the configured path and persist the public DID in
/// `polaris_setup_state`.
///
/// The handler is **idempotent**:
///
/// - If the configured path holds no key (file missing or empty), a
///   fresh K-256 secret is minted and written with mode 0o600. The
///   response carries `already_provisioned = false`.
/// - If the configured path already holds a valid hex-encoded K-256
///   secret, the handler derives its `did:key:z…`, persists it to
///   `polaris_setup_state`, and returns `already_provisioned = true`
///   *without rewriting the file*. This lets the wizard fill the DB
///   record for an operator who pre-provisioned the key (e.g. a
///   smoke-test bootstrap or a migration from a prior labeler) and
///   keeps the labeler signer's in-process key consistent with what
///   gets advertised in steps 2 & 3.
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
/// - [`ApiError::Conflict`] when the configured path holds non-empty
///   content that does not parse as a 32-byte hex K-256 secret
///   (refusing to overwrite or "adopt" a corrupt file is part of the
///   safety contract).
/// - [`ApiError::Internal`] on filesystem failure or DB update
///   failure.
pub async fn generate_key(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<GenerateKeyResponse>, ApiError> {
    let result = generate_key_inner(&state, &ctx).await;
    record_wizard_step("generate_key", result.is_ok());
    result.map(Json)
}

/// Inner generate-key flow. Pulled out of the handler so the metric
/// emission at the call site stays exhaustive (one increment per
/// invocation, success-or-failure) without sprinkling `record_wizard_step`
/// at every `?` site.
async fn generate_key_inner(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
) -> Result<GenerateKeyResponse, ApiError> {
    require_admin(ctx)?;

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

    let (did_key, already_provisioned) = if let Some(existing_did) = adopt_existing_key_did(&path)?
    {
        (existing_did, true)
    } else {
        let (private_hex, fresh_did) = mint_k256_keypair_hex();
        write_private_key_file(&path, &private_hex)?;
        (fresh_did, false)
    };

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

    // REQ-A4: hot-swap the labeler's active signer through the
    // process-wide watch channel. Before this call the slot held a
    // `StubSigner`; afterwards every `emit()` reads through to the
    // freshly-loaded `FilePlainSigner` — no process restart needed.
    // Best-effort: a failed hot-swap is logged but does NOT roll the
    // DB update back. The setup wizard's idempotent re-invocation is
    // the recovery path (the DB row is already correct; a re-POST
    // adopts the same key and re-publishes through the channel).
    hot_swap_signer(state, &path);

    Ok(GenerateKeyResponse {
        did_key,
        already_provisioned,
    })
}

/// REQ-D2: bump `polaris_setup_wizard_steps_total{step,status}`. One
/// invocation per handler-exit; `status` is `"success"` for `Ok`
/// flows and `"failed"` for any `Err` exit. Operators alert on
/// `rate(polaris_setup_wizard_steps_total{status="failed"}[15m]) > 0`
/// to catch a wedged wizard.
fn record_wizard_step(step: &'static str, ok: bool) {
    metrics::counter!(
        "polaris_setup_wizard_steps_total",
        "step" => step,
        "status" => if ok { "success" } else { "failed" },
    )
    .increment(1);
}

/// Load the freshly-written key file as a real
/// [`FilePlainSigner`] and push it through the active-signer watch
/// channel (REQ-A4).
///
/// The channel is held on `ApiState::active_signer_tx`. Production
/// wiring in `main.rs` always installs it; integration tests that
/// exercise AC-A4 install it via [`ApiState::with_active_signer_tx`].
/// When the slot is `None` (test fixtures that don't exercise the
/// hot-swap, or the `--no-labeler` deploy posture) the call is a
/// no-op and a single debug line records the skip.
///
/// Errors at this stage are logged at WARN and discarded so the
/// `generate_key` handler does not surface them to the caller:
///
/// 1. The DB row is already updated — the wizard's view-of-the-world
///    is correct.
/// 2. A subsequent action submission will surface a precise emit-
///    side error if the key is unreadable, and the operator can
///    retry the wizard step (the handler is idempotent — it adopts
///    the existing key on a re-POST).
///
/// The failure modes here are narrow: the file was just written
/// successfully so the only realistic causes are a races against
/// a concurrent file modification or filesystem corruption.
fn hot_swap_signer(state: &ApiState, path: &std::path::Path) {
    let Some(tx) = state.active_signer_tx.as_ref() else {
        tracing::debug!(
            path = %path.display(),
            "no active-signer channel installed; skipping hot-swap (test fixture or --no-labeler deploy)",
        );
        return;
    };
    match FilePlainSigner::from_path(path) {
        Ok(signer) => {
            let new_signer: Arc<dyn SigningKey> = Arc::new(signer);
            let new_did = new_signer.public_key_did().to_owned();
            // `watch::Sender::send` only returns Err when every
            // receiver has been dropped; production wiring keeps a
            // receiver alive on `ApiState::active_signer` for the
            // process lifetime, so this branch fires only in the
            // tear-down phase of a test.
            if let Err(err) = tx.send(new_signer) {
                tracing::warn!(
                    error = %err,
                    "active-signer channel has no live receivers; hot-swap dropped",
                );
            } else {
                tracing::info!(
                    signing_did = %new_did,
                    "hot-swapped labeler signing key into active-signer slot",
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                error = ?err,
                path = %path.display(),
                "freshly-written signing key could not be re-loaded for hot-swap; emit path will reload on next process restart",
            );
        }
    }
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

/// Probe the configured key path; if it already holds a valid K-256
/// secret, return the `did:key:z…` derived from it.
///
/// Three outcomes:
///
/// - `Ok(None)` — file does not exist or exists but is empty. The
///   caller should mint and write a fresh key.
/// - `Ok(Some(did))` — file exists with non-empty content that
///   parses as a 32-byte hex K-256 secret. The caller should adopt
///   this key (persist the did to `polaris_setup_state`, no write).
/// - `Err(ApiError::Conflict)` — file exists with non-empty content
///   that is **not** a valid K-256 secret (wrong length, malformed
///   hex, or unreadable). Refusing to overwrite a non-empty file
///   that doesn't parse keeps an operator's mis-pointed
///   `POLARIS_LABELER_SIGNING_KEY_PATH` from silently destroying
///   whatever lives at the path.
fn adopt_existing_key_did(path: &std::path::Path) -> Result<Option<String>, ApiError> {
    // ENOENT (or anything else that prevents stat) — treat as
    // "no key here yet" and let the fresh-mint path run. A real
    // permission problem will resurface immediately at the
    // create_dir_all / open call with a precise error.
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(None);
    };
    if !meta.is_file() || meta.len() == 0 {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "labeler signing-key file at the configured path exists but could not be read: {e}"
        ))
    })?;
    let hex_str = raw.trim();
    let bytes = hex::decode(hex_str).map_err(|_| {
        ApiError::Conflict(
            "labeler signing-key path holds content that is not valid hex; refusing to overwrite",
        )
    })?;
    if bytes.len() != 32 {
        return Err(ApiError::Conflict(
            "labeler signing-key path holds non-empty content that is not a 32-byte K-256 secret; refusing to overwrite",
        ));
    }
    let kp = K256Keypair::from_private_key(&bytes).map_err(|_| {
        ApiError::Conflict(
            "labeler signing-key path holds 32 bytes that are not a valid K-256 secret scalar; refusing to overwrite",
        )
    })?;
    Ok(Some(kp.did()))
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
    let result = publish_labeler_record_inner(&state, &ctx, req).await;
    record_wizard_step("publish_labeler_record", result.is_ok());
    result.map(Json)
}

/// Inner publish-labeler-record flow. Pulled out so the metric
/// emission is exhaustive (see [`generate_key_inner`]).
async fn publish_labeler_record_inner(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    req: PublishLabelerRecordRequest,
) -> Result<PublishLabelerRecordResponse, ApiError> {
    require_admin(ctx)?;

    let signing_pubkey_did = load_signing_pubkey_did(state).await?;

    // Issue #96 / mod-workstation feature #6: persist the operator-
    // supplied label values + the auto-generated definitions on
    // `polaris_setup_state` so the subscriber-effect preview can
    // serve them locally without a round-trip to the operator's PDS.
    // We clone `req.label_values` here (rather than reading the
    // built record's vector back out) so the persisted shape mirrors
    // the wizard's input verbatim. The definitions are generated by
    // the same `default_definitions_for` helper the record builder
    // uses, so the persisted definitions match the published
    // `labelValueDefinitions` field byte-for-byte.
    let label_values_for_persist = req.label_values.clone();
    let definitions_for_persist =
        polaris_publish_labeler_record::default_definitions_for(&label_values_for_persist);

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

    let verifier = atproto_verifier(state)?;
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
    let response = post_with_dpop_nonce_retry(&oauth_ctx.session, &endpoint, &put_input_value)
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

    // Serialise the auto-generated definitions to JSON for the JSONB
    // column. The shape MUST match what the labeler record published
    // upstream so the subscriber-effect preview reads the same values
    // the AppView sees. `LabelValueDefinition`'s `Serialize` impl
    // (camelCase, skip_serializing_if-None) is the lexicon wire shape;
    // we round-trip through `serde_json::Value` exactly because that's
    // what the policies endpoint will hand back to the frontend.
    let definitions_json = serde_json::to_value(&definitions_for_persist).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "serialising label_value_definitions to JSON failed: {e}"
        ))
    })?;

    sqlx::query!(
        r"UPDATE polaris_setup_state
          SET labeler_record_uri = $1,
              label_values = $2,
              label_value_definitions = $3,
              updated_at = now()
          WHERE id = TRUE",
        &at_uri,
        &label_values_for_persist,
        definitions_json,
    )
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(PublishLabelerRecordResponse { at_uri, cid })
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
    let result = request_plc_signature_inner(&state, &ctx).await;
    record_wizard_step("request_plc_signature", result.is_ok());
    result.map(Json)
}

/// Inner request-plc-signature flow. Pulled out for metric exhaustivity.
async fn request_plc_signature_inner(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
) -> Result<RequestPlcSignatureResponse, ApiError> {
    require_admin(ctx)?;

    let verifier = atproto_verifier(state)?;
    let oauth_ctx = verifier
        .build_oauth_session_for_moderator(ctx.moderator_id)
        .await
        .map_err(|e| map_oauth_setup_error(&e))?;

    // The lexicon for `requestPlcOperationSignature` declares **no
    // input**. bsky.social's PDS strictly rejects any body (`400
    // InvalidRequest "A request body was provided when none was
    // expected"`), so we bypass `OAuthSession::post` (which always
    // serialises a JSON body) and use a bodyless DPoP-bound POST
    // helper that builds the proof from the context's bound key.
    let endpoint = format!(
        "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
        oauth_ctx.pds_url
    );
    let response = post_no_body_with_dpop_nonce_retry(&oauth_ctx, &endpoint)
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

    Ok(RequestPlcSignatureResponse {
        message: "Check your email for the PLC operation token. The email comes from your PDS."
            .to_owned(),
    })
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
pub async fn submit_plc_operation(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(req): Json<SubmitPlcOperationRequest>,
) -> Result<Json<SubmitPlcOperationResponse>, ApiError> {
    let result = submit_plc_operation_inner(&state, &ctx, req).await;
    // REQ-D2: a single `polaris_plc_operations_total{status}` increment
    // per invocation captures PDS-side success or failure. The setup-
    // wizard step counter (`polaris_setup_wizard_steps_total`) fires
    // alongside so an operator can correlate the two (a step that
    // fails because the PDS rejected the signed op vs. one that fails
    // before reaching the PDS).
    let ok = result.is_ok();
    metrics::counter!(
        "polaris_plc_operations_total",
        "status" => if ok { "success" } else { "failed" },
    )
    .increment(1);
    record_wizard_step("submit_plc_operation", ok);
    result.map(Json)
}

/// Inner submit-plc-operation flow. Pulled out for metric exhaustivity.
#[allow(
    clippy::too_many_lines,
    reason = "5-step PLC flow (lookup → build payloads → sign → submit → persist) reads more clearly as one linear function than a chain of micro-helpers"
)]
async fn submit_plc_operation_inner(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    req: SubmitPlcOperationRequest,
) -> Result<SubmitPlcOperationResponse, ApiError> {
    require_admin(ctx)?;

    // The labeler's signing public DID (did:key:z…) is needed both
    // as a precondition (step 1 must have run) and as the value that
    // gets published as the `#atproto_label` verification method in
    // the DID document so downstream consumers can verify the
    // signatures on emitted labels.
    let signing_pubkey_did = load_signing_pubkey_did(state).await?;

    let verifier = atproto_verifier(state)?;
    let oauth_ctx = verifier
        .build_oauth_session_for_moderator(ctx.moderator_id)
        .await
        .map_err(|e| map_oauth_setup_error(&e))?;

    // PLC operations are full-snapshot REPLACE semantics on every
    // field of `signPlcOperation::Input`: omitting a field tells the
    // PDS to preserve the current value; including a field tells the
    // PDS to use exactly that value (no merging). For
    // `polarislabeler.bsky.social` (a did:plc account) the existing
    // verification methods (`atproto`) and the existing service
    // (`atproto_pds`) MUST be preserved — replacing them would
    // overwrite bsky.social's identity key for the account and
    // remove the PDS service entry, breaking login.
    //
    // We resolve the current DID document, splice the wizard's
    // `atproto_labeler` service entry on top of the existing
    // services map, and submit ONLY `services` — omitting
    // `verificationMethods`, `alsoKnownAs`, and `rotationKeys`
    // entirely so the PDS preserves them.
    let current_doc = verifier
        .resolve_did_document(&oauth_ctx.did)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, did = %oauth_ctx.did, "could not resolve current DID document for PLC update");
            ApiError::Internal(anyhow::anyhow!("could not resolve current DID document"))
        })?;
    let services_payload = build_plc_services_with_labeler(&current_doc, &req.service_url);
    let verification_methods_payload =
        build_plc_verification_methods_with_label(&current_doc, &signing_pubkey_did);

    // Sign the PLC operation. We send `services` + `verificationMethods`
    // (both pre-merged so the existing `#atproto` key + `#atproto_pds`
    // service are preserved alongside the new labeler entries); the
    // rest of `signPlcOperation::Input` (alsoKnownAs / rotationKeys)
    // is omitted so the PDS preserves the current values.
    let sign_body = serde_json::json!({
        "token": req.token,
        "services": services_payload,
        "verificationMethods": verification_methods_payload,
    });
    let sign_endpoint = format!(
        "{}/xrpc/com.atproto.identity.signPlcOperation",
        oauth_ctx.pds_url
    );
    let sign_response = post_with_dpop_nonce_retry(&oauth_ctx.session, &sign_endpoint, &sign_body)
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
    let submit_response =
        post_with_dpop_nonce_retry(&oauth_ctx.session, &submit_endpoint, &submit_body)
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

    Ok(SubmitPlcOperationResponse { did: oauth_ctx.did })
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

/// Build the `verificationMethods` map for `signPlcOperation`,
/// preserving the account's existing verification methods (e.g. the
/// PDS-controlled `#atproto` identity key) and splicing in (or
/// replacing) `atproto_label` pointing at the labeler's signing key.
///
/// Without this entry, downstream `AppViews` have no published key to
/// verify the signature on labels we emit — the labeler would be
/// registered but its emitted labels would be unverifiable.
/// `verificationMethods` is REPLACE-on-presence, so we MUST include
/// the existing `#atproto` entry alongside the new `#atproto_label`
/// one, otherwise the PDS-controlled identity key gets clobbered and
/// the account's normal login flow breaks.
///
/// Entries whose `public_key_multibase` is absent are skipped (the
/// PLC map values are required to be `did:key:` strings, and an
/// entry without multibase material cannot produce one).
fn build_plc_verification_methods_with_label(
    current_doc: &proto_blue::common::DidDocument,
    labeler_signing_pubkey_did: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for vm in &current_doc.verification_method {
        let fragment = vm
            .id
            .rsplit_once('#')
            .map_or(vm.id.as_str(), |(_, suffix)| suffix);
        let Some(multibase) = vm.public_key_multibase.as_deref() else {
            continue;
        };
        map.insert(
            fragment.to_owned(),
            serde_json::Value::String(format!("did:key:{multibase}")),
        );
    }
    map.insert(
        polaris_publish_did_service::ATPROTO_LABEL_VERIFICATION_ID
            .trim_start_matches('#')
            .to_owned(),
        serde_json::Value::String(labeler_signing_pubkey_did.to_owned()),
    );
    serde_json::Value::Object(map)
}

/// Build the `services` map for `signPlcOperation`, preserving the
/// account's existing service entries and splicing in (or replacing)
/// `atproto_labeler` to point at `service_url`.
///
/// PLC operations REPLACE on presence, so the wizard must send the
/// **full** current set of services plus the new `atproto_labeler`
/// entry. We translate `DidDocument::service` (W3C DID-Core
/// `[{id, type, serviceEndpoint}]` shape) into the PLC `Map<fragment,
/// {type, endpoint}>` shape, fragment-keyed by the suffix after `#`
/// in each `id`. Service entries whose `serviceEndpoint` is not a
/// JSON string are skipped — the PLC lexicon expects a string
/// endpoint; an object-shaped W3C entry (rare) would be rejected by
/// the directory anyway.
fn build_plc_services_with_labeler(
    current_doc: &proto_blue::common::DidDocument,
    service_url: &str,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for service in &current_doc.service {
        let fragment = service
            .id
            .rsplit_once('#')
            .map_or(service.id.as_str(), |(_, suffix)| suffix);
        // Preserve string-shaped endpoints; skip exotic object-shaped
        // serviceEndpoint values (W3C allows them but PLC doesn't).
        let Some(endpoint_str) = service.service_endpoint.as_str() else {
            continue;
        };
        map.insert(
            fragment.to_owned(),
            serde_json::json!({
                "type": service.service_type,
                "endpoint": endpoint_str,
            }),
        );
    }
    // Splice in (or overwrite) the labeler entry.
    map.insert(
        polaris_publish_did_service::LABELER_SERVICE_ID
            .trim_start_matches('#')
            .to_owned(),
        serde_json::json!({
            "type": polaris_publish_did_service::LABELER_SERVICE_TYPE,
            "endpoint": service_url,
        }),
    );
    serde_json::Value::Object(map)
}

/// POST `endpoint` with **no body** through the moderator's bound
/// DPoP key, with a single `use_dpop_nonce` retry.
///
/// proto-blue 0.3.2's `OAuthSession::post` always serialises and
/// transmits a JSON body — even for an empty object `{}`. The
/// `com.atproto.identity.requestPlcOperationSignature` lexicon
/// declares **no input**, so the PDS rejects any request that
/// carries a body (`400 InvalidRequest "A request body was provided
/// when none was expected"`). This helper bypasses
/// `OAuthSession::post` and uses the context's `dpop_key`,
/// `dpop_nonces`, `access_token`, and `fetcher` to build a bodyless
/// DPoP-signed POST directly via the same `FetchHandler` the session
/// would use, so the request looks identical on the wire except for
/// the absent body / `content-type`.
async fn post_no_body_with_dpop_nonce_retry(
    ctx: &crate::auth::atproto::ModeratorOAuthContext,
    endpoint: &str,
) -> Result<proto_blue::common::fetch::HttpResponse, proto_blue::oauth::OAuthError> {
    let first = post_no_body_once(ctx, endpoint).await?;
    if is_use_dpop_nonce_response(&first) {
        // The first response's DPoP-Nonce header was absorbed into
        // ctx.dpop_nonces by post_no_body_once before returning; the
        // retry will pick it up.
        tracing::debug!(
            endpoint = %endpoint,
            "resource server challenged bodyless POST with use_dpop_nonce; retrying"
        );
        return post_no_body_once(ctx, endpoint).await;
    }
    Ok(first)
}

/// One bodyless DPoP-bound POST attempt. Absorbs any `DPoP-Nonce`
/// response header into `ctx.dpop_nonces` before returning so the
/// caller's retry (and any subsequent `OAuthSession::post` against
/// the same origin) sees the rotated nonce.
async fn post_no_body_once(
    ctx: &crate::auth::atproto::ModeratorOAuthContext,
    endpoint: &str,
) -> Result<proto_blue::common::fetch::HttpResponse, proto_blue::oauth::OAuthError> {
    use proto_blue::common::fetch::HttpRequest;
    use proto_blue::oauth::build_dpop_proof;

    let origin = url::Url::parse(endpoint)
        .ok()
        .map(|u| u.origin().ascii_serialization());
    let nonce = origin.as_ref().and_then(|o| ctx.dpop_nonces.get(o));

    // `htu` must omit query + fragment per RFC 9449 §4.2.
    let htu = strip_query_fragment(endpoint);
    let proof = build_dpop_proof(
        &ctx.dpop_key,
        "POST",
        &htu,
        nonce.as_deref(),
        Some(&ctx.access_token),
    )?;

    let req = HttpRequest::post(endpoint)
        .with_header("authorization", format!("DPoP {}", ctx.access_token))
        .with_header("dpop", proof);

    let resp = ctx.fetcher.fetch(req).await?;

    // Mirror OAuthSession::request: absorb the response nonce before
    // returning so the next attempt (or any session.post call against
    // the same origin) carries it.
    if let (Some(origin), Some(nonce_str)) = (origin.as_ref(), resp.header("dpop-nonce")) {
        ctx.dpop_nonces.set(origin, nonce_str);
    }

    Ok(resp)
}

/// Strip the `?query` and `#fragment` from `url`, returning the base.
/// Falls back to the original string when `url` does not parse — the
/// DPoP proof will then carry the raw input and the server's
/// signature validation will reject any malformed `htu` cleanly.
fn strip_query_fragment(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => url.to_owned(),
    }
}

/// POST `body` to `endpoint` through the moderator's OAuth session and
/// retry **once** on a `use_dpop_nonce` server challenge.
///
/// Resource servers (e.g. bsky.social's PDS) require DPoP proofs to
/// carry a server-issued `nonce` claim. The first request from a
/// freshly-reconstructed [`OAuthSession`] cannot carry that nonce
/// because the cache is empty (the proto-blue 0.3.2 `OAuthSession`
/// keeps the cache per-instance and `build_oauth_session_for_moderator`
/// re-instantiates it on every call). The server responds with a
/// `use_dpop_nonce` challenge — body JSON `{"error":"use_dpop_nonce",
/// …}` and either a `401` (PDS / resource-server form) or `400` (AS
/// form). The session **does** auto-absorb the `DPoP-Nonce` header
/// from the response into its cache, so a single retry from the same
/// session will carry the right nonce and succeed.
///
/// The retry is bounded to one extra attempt: if the server still
/// challenges after that, the failure is genuine (token expired,
/// scope mismatch, …) and we surface it to the caller verbatim.
async fn post_with_dpop_nonce_retry(
    session: &proto_blue::oauth::OAuthSession,
    endpoint: &str,
    body: &serde_json::Value,
) -> Result<proto_blue::common::fetch::HttpResponse, proto_blue::oauth::OAuthError> {
    let first = session.post(endpoint, body).await?;
    if is_use_dpop_nonce_response(&first) {
        // The session.post body above also wrote the new nonce into
        // the session's DpopNonceCache (see proto-blue-oauth 0.3.2
        // session.rs `if let Some(nonce_str) = resp.header(...)`);
        // a single retry from the same session picks it up.
        tracing::debug!(
            endpoint = %endpoint,
            "resource server challenged with use_dpop_nonce; retrying with fresh nonce"
        );
        return session.post(endpoint, body).await;
    }
    Ok(first)
}

/// True when `resp` is a `use_dpop_nonce` challenge. Matches both the
/// AS-style `400 {"error":"use_dpop_nonce"}` and the RS-style
/// `401 …` (either WWW-Authenticate-carried or body-carried; bsky's
/// PDS uses the body-carried form).
fn is_use_dpop_nonce_response(resp: &proto_blue::common::fetch::HttpResponse) -> bool {
    if resp.status != 401 && resp.status != 400 {
        return false;
    }
    if let Some(auth) = resp.header("www-authenticate") {
        if auth.contains("error=\"use_dpop_nonce\"") {
            return true;
        }
    }
    if let Ok(body) = std::str::from_utf8(&resp.body) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if v.get("error").and_then(|e| e.as_str()) == Some("use_dpop_nonce") {
                return true;
            }
        }
    }
    false
}

/// Map a `build_oauth_session_for_moderator` error to an
/// `ApiError`. The opaque mapping is deliberate: every
/// auth-side variant (session not found, crypto failure, JWK
/// shape mismatch) surfaces as a generic 500 so the wire
/// shape does not leak why the per-moderator OAuth session
/// is unusable.
fn map_oauth_setup_error(err: &crate::auth::AuthError) -> ApiError {
    // Walk the source chain so diagnostics like "DPoP binding failed"
    // surface the underlying cause (serde shape mismatch, missing JWK
    // field, K-256 import failure, …) — the top-level Display alone
    // gives the operator no actionable signal.
    let mut chain = format!("{err}");
    let mut next: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(cause) = next {
        chain.push_str(" -> ");
        chain.push_str(&cause.to_string());
        next = cause.source();
    }
    tracing::warn!(
        error = %err,
        chain = %chain,
        "setup endpoint failed to rebuild moderator OAuth session"
    );
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

    // Coverage for the file-state probe lives at the integration
    // level in `tests/setup_endpoints.rs::generate_key_conflict_on_existing_file`,
    // which drives the whole admin-gated handler against a real
    // Postgres testcontainer and asserts the 409 response shape.
    // The earlier unit-level shims referenced a helper that was
    // refactored away into [`adopt_existing_key_did`]; the
    // integration test is the load-bearing assertion now.

    #[test]
    fn adopt_existing_key_did_returns_none_for_missing_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist.key");
        assert!(
            adopt_existing_key_did(&path)
                .expect("missing path is fine")
                .is_none(),
            "missing path must be the fresh-mint path (None)",
        );
    }

    #[test]
    fn adopt_existing_key_did_returns_none_for_empty_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        assert!(
            adopt_existing_key_did(tmp.path())
                .expect("empty file is the fresh-mint path")
                .is_none(),
        );
    }

    #[test]
    fn adopt_existing_key_did_rejects_corrupt_nonempty_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(tmp.path(), "not-hex-content").unwrap();
        let err = adopt_existing_key_did(tmp.path())
            .expect_err("non-empty malformed content must surface Conflict");
        assert!(matches!(err, ApiError::Conflict(_)), "got {err:?}");
    }
}
