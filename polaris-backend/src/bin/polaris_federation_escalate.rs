//! `polaris-federation-escalate` — admin command for cross-instance federation.
//!
//! Issues a signed escalation record to the operator's own ATProto repo under
//! `gay.dollspace.polaris.escalation`, addressed to a specific peer instance.
//! The record is indexed by the peer's Firehose subscription (PR 1 / #107);
//! once the peer materialises it, the escalation enters their case stream
//! (PR 2 / #108).
//!
//! # Privacy
//!
//! The wire record is produced by
//! `polaris_types::lexicon_mapping::to_lexicon_escalation` — the mapping
//! function that strips internal-only fields before any bytes leave the
//! Polaris trust boundary (REQ-5 / AC-4):
//!
//! - `Escalation::id` is dropped at the mapping boundary.
//! - The `Escalation` struct itself never carries `moderator_id`,
//!   `audit_chain_hash`, `reporter_did`, or `exposure_metadata` — those
//!   fields are excluded at construction time (this binary) by only
//!   populating the public-safe fields from the incident row.
//!
//! # Authentication
//!
//! The record is signed by the labeler K-256 key whose active form is loaded
//! via [`AppConfig::from_env`]. The binary constructs the signer directly
//! (no running process required) and wires it into a one-shot
//! [`OutboundPublisher`].
//!
//! # Exit codes
//!
//! - `0` — success; the resulting CID is printed to stdout.
//! - `1` — user error (bad flags, missing env).
//! - `2` — external dependency error (PDS unreachable, XRPC failure).
//! - `3` — internal error (DB query failed, signer construction failed).

#![doc(html_no_source)]

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;
use polaris_backend::config::AppConfig;
use polaris_backend::db;
use polaris_backend::federation::publish::OutboundPublisher;
use polaris_backend::labeler::signer::build_signing_key;
use polaris_backend::repo::{IncidentRepo as _, PgIncidentRepo, SubjectRepo as _};
use polaris_types::escalation::{Escalation, SubjectRef};
use polaris_types::ids::{Did, EscalationId, IncidentId};
use tokio::sync::watch;
use tracing::info;
use uuid::Uuid;

const EXIT_USER_ERROR: u8 = 1;
const EXIT_EXTERNAL_ERROR: u8 = 2;
const EXIT_INTERNAL_ERROR: u8 = 3;

/// Issue a cross-instance federation escalation to a peer Polaris instance.
///
/// Writes a signed `gay.dollspace.polaris.escalation` record to the
/// operator's ATProto repo. The peer's Firehose subscription picks it up
/// and materialises it into their case stream.
#[derive(Debug, Parser)]
#[command(
    name = "polaris-federation-escalate",
    version,
    about = "Publish a signed federation escalation to a peer Polaris instance.",
    long_about = "Publish a signed federation escalation record to the operator's ATProto repo.\n\n\
        The record is addressed to the target instance's DID and carries a \
        federation-safe summary of the named incident. Internal-only fields \
        (moderator identity, audit hashes, reporter DIDs) are never included \
        in the Escalation struct and never reach the wire.\n\n\
        Prerequisites:\n  \
        DATABASE_URL — Postgres connection to look up the incident.\n  \
        POLARIS_LOCAL_DID — operator's own ATProto DID (the repo written to).\n  \
        POLARIS_PDS_URL — PDS endpoint for XRPC repo writes.\n  \
        Labeler signing-key env vars (same as the live server).\n\n\
        Exit codes:\n  \
        0 — success (CID printed to stdout)\n  \
        1 — user error (bad flags, missing env)\n  \
        2 — external dependency error (PDS / network)\n  \
        3 — internal error (DB, signer)"
)]
struct Cli {
    /// Internal incident UUID to escalate.
    ///
    /// The incident must exist in the local Postgres instance reachable
    /// via `DATABASE_URL`. Its public-safe fields are used to build the
    /// escalation record; internal-only fields are never included.
    #[arg(long, value_name = "UUID")]
    incident: Uuid,

    /// ATProto DID of the target peer instance.
    ///
    /// The escalation is addressed to this DID. The peer's federation
    /// worker must be subscribed to the operator's repo Firehose for
    /// delivery.
    #[arg(long, value_name = "DID")]
    to: String,

    /// Federation-safe escalation reason (free text).
    ///
    /// Sent verbatim in the wire record. Must not contain PII or
    /// internal identifiers — this text is visible to the peer operator.
    #[arg(long, value_name = "REASON")]
    reason: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(cid) => {
            println!("{cid}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            let code = classify_error(&err);
            tracing::error!(error = %err, exit_code = code, "federation escalation failed");
            let _ = writeln!(std::io::stderr(), "error: {err:#}");
            ExitCode::from(code)
        }
    }
}

async fn run(cli: Cli) -> Result<String> {
    // ── 1. Configuration ────────────────────────────────────────────────
    let cfg = AppConfig::from_env().context("loading AppConfig from environment")?;

    let local_did = std::env::var("POLARIS_LOCAL_DID").ok();
    if local_did.is_none() {
        tracing::warn!(
            "POLARIS_LOCAL_DID is unset; \
             the escalation record will fail at the publisher"
        );
    }

    let pds_url =
        std::env::var("POLARIS_PDS_URL").context("POLARIS_PDS_URL must be set for repo writes")?;

    // ── 2. Database: look up the incident ───────────────────────────────
    let incident_id = IncidentId(cli.incident);

    let db = db::connect(&cfg.db)
        .await
        .context("connecting to Postgres")?;
    let pool = db.pool().clone();

    let incident = PgIncidentRepo::new(pool.clone())
        .get(incident_id)
        .await
        .context("looking up incident in Postgres")?
        .with_context(|| format!("incident {incident_id} not found"))?;

    // ── 3. Look up the primary subject's DID ────────────────────────────
    // The `Escalation` requires a `SubjectRef` (DID or AT-URI) identifying
    // the account or record being escalated. The incident carries a `SubjectId`
    // (internal UUID); we look up the subject row to get the ATProto DID.
    let subject_row = polaris_backend::repo::PgSubjectRepo::new(pool)
        .get(incident.primary_subject)
        .await
        .context("looking up subject DID from Postgres")?
        .with_context(|| {
            format!(
                "subject {} for incident {incident_id} not found",
                incident.primary_subject
            )
        })?;

    let subject = match subject_row.did {
        Some(did) => SubjectRef::Did(did.0),
        None => {
            // If the subject has no DID (e.g. cohort-only subject), we
            // cannot form a valid ATProto escalation — federation requires
            // an ATProto-addressable subject.
            anyhow::bail!(
                "subject {} has no ATProto DID; cannot federate",
                incident.primary_subject
            );
        }
    };

    // ── 4. Build the Escalation struct ──────────────────────────────────
    // PRIVACY: only public-safe fields are included.
    // - moderator_id → NEVER included; not part of Escalation struct
    // - audit_chain_hash → NEVER included; not part of Escalation struct
    // - reporter DIDs → NEVER included; not part of Escalation struct
    // - exposure_metadata → NEVER included; not part of Escalation struct
    //
    // The Escalation struct itself enforces this by design: it only has
    // fields that are safe to federate. See polaris_types::escalation.
    let escalation = Escalation {
        id: EscalationId::new(),
        source_did: Did::new(local_did.clone().unwrap_or_default()),
        target_did: Did::new(cli.to.clone()),
        subject,
        reason: cli.reason.clone(),
        observations: vec![], // pattern evidence added via follow-up (#110)
        evidence: vec![],     // evidence pointers added via evidence subsystem
        created_at: incident.opened_at,
    };

    info!(
        incident_id = %incident_id,
        target = %cli.to,
        escalation_id = %escalation.id,
        "issuing federation escalation",
    );

    // ── 5. Build signer and wire up watch channel ────────────────────────
    let signer = build_signing_key(&cfg.labeler.signing_key, cfg.profile)
        .context("building labeler signing key")?;
    let (_signer_tx, signer_rx) = watch::channel(signer);

    // ── 6. Build XRPC client ─────────────────────────────────────────────
    let xrpc = proto_blue::xrpc::XrpcClient::new(&pds_url)
        .context("building XRPC client for PDS")?;

    // ── 7. Publish ───────────────────────────────────────────────────────
    let publisher = OutboundPublisher::new(signer_rx, Arc::new(xrpc), local_did);
    let cid = publisher
        .publish_escalation(&escalation)
        .await
        .context("publishing escalation record to ATProto repo")?;

    info!(
        escalation_id = %escalation.id,
        target = %cli.to,
        cid = %cid,
        "federation escalation published successfully",
    );

    Ok(cid)
}

/// Map the anyhow error chain to an exit-code category.
///
/// The categories mirror the convention from `labeler-key-rotate` so
/// operators can build monitoring on exit-code ranges.
fn classify_error(err: &anyhow::Error) -> u8 {
    for cause in err.chain() {
        let msg = cause.to_string();
        if msg.contains("POLARIS_LOCAL_DID")
            || msg.contains("POLARIS_PDS_URL")
            || msg.contains("not found")
        {
            return EXIT_USER_ERROR;
        }
        if msg.contains("ATProto repo write failed")
            || msg.contains("building XRPC client for PDS")
        {
            return EXIT_EXTERNAL_ERROR;
        }
    }
    EXIT_INTERNAL_ERROR
}
