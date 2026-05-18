//! Per-peer Firehose subscription worker.
//!
//! [`run_peer_worker`] opens one [`proto_blue::repo::Firehose`] connection per
//! configured peer, filters incoming commit events to NSIDs that start with
//! `gay.dollspace.polaris.`, verifies the commit signature, and inserts
//! matched records into `federation_quarantine`.
//!
//! # Cancel safety
//!
//! The Firehose future is driven in a dedicated pump task (spawned inside
//! [`run_peer_worker`]) that races `firehose.next_event()` against the
//! [`tokio_util::sync::CancellationToken`] only. The outer worker task reads
//! from the pump's internal channel — an `mpsc::recv()` is cancel-safe, so
//! the outer `tokio::select!` never drops a partially-received event.
//!
//! This mirrors the pump/consume split in [`crate::ingest::firehose`].
//!
//! # Reconnect
//!
//! On transport error the pump rebuilds the [`Firehose`] with exponential
//! backoff (1 s → 2 s → 4 s → … capped at 60 s) per the task spec.
//!
//! # Idempotent insert
//!
//! Quarantine inserts use `ON CONFLICT (cid) DO NOTHING` so replay on
//! reconnect is safe.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{FederationError, PeerConfig};
use crate::federation::verify::PeerKeyResolver;

// ── constants ─────────────────────────────────────────────────────────────

/// NSID prefix that all Polaris federation records must carry.
const POLARIS_NSID_PREFIX: &str = "gay.dollspace.polaris.";

/// Initial reconnect delay (the `T₀` of `T₀ × 2^attempt`).
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Maximum reconnect delay cap.
const BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Capacity of the internal pump → worker channel.
const PUMP_CHANNEL_CAPACITY: usize = 32;

// ── pump-side event envelope ──────────────────────────────────────────────

/// One item forwarded from the pump task to the consuming worker.
enum PumpItem {
    /// A decoded commit event from the firehose. Boxed to keep the enum
    /// variant sizes comparable (`CommitEvent` contains a `Vec<RepoOp>` + `Vec<u8>`
    /// which is significantly larger than `RepoError`).
    Event(Box<proto_blue::repo::CommitEvent>),
    /// The pump encountered a transport/decode error; the consumer should
    /// log it and wait for the next delivery (the pump reconnects internally).
    Err(proto_blue::repo::RepoError),
}

// ── public entry point ────────────────────────────────────────────────────

/// Drive a single peer subscription to completion.
///
/// This function runs until:
/// - `cancel` is fired (returns `Ok(())`).
/// - A fatal database error occurs (returns `Err`).
///
/// Non-fatal errors (transport failures, decode errors, bad signatures) are
/// logged and the worker continues.
///
/// # Errors
///
/// Returns [`FederationError::QuarantineWriteFailed`] on any fatal Postgres
/// error.
pub async fn run_peer_worker(
    peer: PeerConfig,
    pool: PgPool,
    resolver: Arc<PeerKeyResolver>,
    cancel: CancellationToken,
) -> Result<(), FederationError> {
    info!(peer_did = %peer.did, "federation peer worker starting");

    // Build the initial firehose URL. atproto's `subscribeRepos` lives at the
    // PDS's XRPC path. We resolve the PDS via the same resolver path used for
    // the signing key; for now we derive the WSS URL from the DID's PDS
    // endpoint stored in the peer config.
    let subscribe_url = build_subscribe_url(&peer);

    let (pump_tx, mut pump_rx) = mpsc::channel::<PumpItem>(PUMP_CHANNEL_CAPACITY);
    let pump_cancel = cancel.clone();
    let pump_url = subscribe_url.clone();

    // Spawn the pump in a sibling task so the firehose future is never inside
    // a `select!`. This guarantees cancel-safety on the consumer side.
    let pump_handle = tokio::spawn(async move {
        run_pump(pump_url, pump_tx, pump_cancel).await;
    });

    let result = run_consume_loop(&peer, pool, resolver, &cancel, &mut pump_rx).await;

    // Signal the pump to stop and wait for clean exit.
    cancel.cancel();
    let _ = pump_handle.await;

    result
}

// ── pump ──────────────────────────────────────────────────────────────────

/// Drive `Firehose::next_event` in a tight, un-selected loop.
///
/// The pump reconnects with exponential backoff on transport errors and
/// forwards every decoded commit event (or per-reconnect error) over `tx`.
/// It exits when `cancel` fires or `tx.send` returns an error (consumer gone).
async fn run_pump(subscribe_url: String, tx: mpsc::Sender<PumpItem>, cancel: CancellationToken) {
    let mut backoff_secs = BACKOFF_INITIAL;
    let mut firehose = proto_blue::repo::Firehose::new(subscribe_url.clone());

    loop {
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            res = firehose.next_event() => res,
        };

        match outcome {
            Ok(Some(proto_blue::repo::FirehoseEvent::Commit(commit))) => {
                // Reset backoff on a good frame.
                backoff_secs = BACKOFF_INITIAL;
                if tx.send(PumpItem::Event(Box::new(commit))).await.is_err() {
                    // Consumer dropped its receiver; nothing to do.
                    return;
                }
            }
            Ok(Some(_)) => {
                // Non-commit events (identity, account, info, etc.) are not
                // interesting to federation ingestion; skip silently.
            }
            Ok(None) => {
                // Clean stream close — reconnect immediately.
                debug!("firehose stream closed cleanly; reconnecting");
                firehose = proto_blue::repo::Firehose::new(subscribe_url.clone());
            }
            Err(proto_blue::repo::RepoError::FirehoseError { error, message }) => {
                warn!(
                    error = %error,
                    message = ?message,
                    "firehose server error frame; reconnecting after backoff",
                );
                apply_backoff(&mut backoff_secs, &cancel).await;
                firehose = proto_blue::repo::Firehose::new(subscribe_url.clone());
            }
            Err(err) => {
                warn!(error = ?err, "firehose transport/decode error");
                // Forward the error so the consumer can log it, then reconnect.
                let _ = tx.send(PumpItem::Err(err)).await;
                apply_backoff(&mut backoff_secs, &cancel).await;
                firehose = proto_blue::repo::Firehose::new(subscribe_url.clone());
            }
        }
    }
}

/// Sleep for `backoff_secs`, then double it (capped at [`BACKOFF_CAP`]).
///
/// Races the sleep against `cancel` so SIGINT is honoured during backoff.
async fn apply_backoff(backoff: &mut Duration, cancel: &CancellationToken) {
    let sleep_dur = *backoff;
    *backoff = (*backoff * 2).min(BACKOFF_CAP);
    tokio::select! {
        biased;
        () = cancel.cancelled() => {},
        () = tokio::time::sleep(sleep_dur) => {},
    }
}

// ── consumer loop ─────────────────────────────────────────────────────────

/// Receive decoded commits from the pump, filter/verify, and quarantine.
async fn run_consume_loop(
    peer: &PeerConfig,
    pool: PgPool,
    resolver: Arc<PeerKeyResolver>,
    cancel: &CancellationToken,
    pump_rx: &mut mpsc::Receiver<PumpItem>,
) -> Result<(), FederationError> {
    loop {
        // `mpsc::Receiver::recv` is cancel-safe: a dropped future does not
        // consume a queued message.
        let item = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                info!(peer_did = %peer.did, "federation worker cancelled; exiting");
                return Ok(());
            }
            item = pump_rx.recv() => match item {
                Some(i) => i,
                None => {
                    // Pump task exited; nothing more to consume.
                    return Ok(());
                }
            },
        };

        match item {
            PumpItem::Err(err) => {
                warn!(
                    peer_did = %peer.did,
                    error = ?err,
                    "received pump error; continuing",
                );
            }
            PumpItem::Event(commit) => {
                handle_commit(peer, &pool, &resolver, *commit).await?;
            }
        }
    }
}

// ── per-commit handler ────────────────────────────────────────────────────

/// Process one [`CommitEvent`] from the peer's firehose.
///
/// Filters `ops` to Polaris NSIDs, verifies the commit signature, and
/// inserts matching records into `federation_quarantine`.
///
/// # Errors
///
/// Returns [`FederationError::QuarantineWriteFailed`] on Postgres errors.
async fn handle_commit(
    peer: &PeerConfig,
    pool: &PgPool,
    resolver: &Arc<PeerKeyResolver>,
    commit: proto_blue::repo::CommitEvent,
) -> Result<(), FederationError> {
    let polaris_ops = filter_polaris_ops(&commit);
    if polaris_ops.is_empty() {
        return Ok(());
    }

    debug!(
        peer_did = %peer.did,
        ops_count = polaris_ops.len(),
        "processing commit with Polaris ops",
    );

    let (_, block_map) = parse_commit_car(peer, &commit.blocks)?;
    let commit_cid_str = commit.commit.to_string();
    let sig_status =
        verify_and_classify(peer, resolver, &commit, &block_map, &commit_cid_str).await;

    quarantine_ops(
        peer,
        pool,
        &polaris_ops,
        &block_map,
        &commit_cid_str,
        sig_status,
    )
    .await
}

/// Filter a commit's ops to creates/updates of Polaris-namespaced records.
fn filter_polaris_ops(commit: &proto_blue::repo::CommitEvent) -> Vec<&proto_blue::repo::RepoOp> {
    commit
        .ops
        .iter()
        .filter(|op| {
            op.path
                .split('/')
                .next()
                .is_some_and(|col| col.starts_with(POLARIS_NSID_PREFIX))
        })
        .filter(|op| {
            matches!(
                op.action,
                proto_blue::repo::RepoOpAction::Create | proto_blue::repo::RepoOpAction::Update
            )
        })
        .collect()
}

/// Parse the commit CAR. Returns `Err(RepoFetchFailed)` on parse failure.
fn parse_commit_car(
    peer: &PeerConfig,
    blocks: &[u8],
) -> Result<(Vec<proto_blue::lex_data::Cid>, proto_blue::repo::BlockMap), FederationError> {
    proto_blue::repo::read_car(blocks).map_err(|e| {
        warn!(peer_did = %peer.did, error = ?e, "failed to parse CAR from commit");
        FederationError::RepoFetchFailed {
            did: peer.did.clone(),
            message: format!("CAR parse failed: {e}"),
        }
    })
}

/// Verify the commit signature and return the `signature_status` string.
///
/// Logs at WARN and invalidates the key cache on failure. Returns `"verified"`
/// on success or `"verify_failed"` on any non-fatal sig/parse error.
async fn verify_and_classify(
    peer: &PeerConfig,
    resolver: &Arc<PeerKeyResolver>,
    commit: &proto_blue::repo::CommitEvent,
    block_map: &proto_blue::repo::BlockMap,
    commit_cid_str: &str,
) -> &'static str {
    match resolve_and_verify_commit_sig(peer, resolver, commit, block_map, commit_cid_str).await {
        Ok(_) => "verified",
        Err(FederationError::SignatureVerifyFailed { .. }) => {
            warn!(
                peer_did = %peer.did,
                cid = %commit_cid_str,
                "commit signature verification failed; quarantining as 'verify_failed'",
            );
            resolver.invalidate(&peer.did).await;
            "verify_failed"
        }
        Err(err) => {
            warn!(
                peer_did = %peer.did,
                cid = %commit_cid_str,
                error = ?err,
                "could not verify commit block; quarantining as 'verify_failed'",
            );
            "verify_failed"
        }
    }
}

/// Insert each matching op into `federation_quarantine`.
///
/// # Errors
///
/// Returns [`FederationError::QuarantineWriteFailed`] on Postgres errors.
async fn quarantine_ops(
    peer: &PeerConfig,
    pool: &PgPool,
    polaris_ops: &[&proto_blue::repo::RepoOp],
    block_map: &proto_blue::repo::BlockMap,
    commit_cid_str: &str,
    sig_status: &str,
) -> Result<(), FederationError> {
    for op in polaris_ops {
        let Some(record_cid) = &op.cid else {
            warn!(peer_did = %peer.did, path = %op.path, "op has no CID; skipping");
            continue;
        };
        let record_cid_str = record_cid.to_string();
        let nsid = op
            .path
            .split('/')
            .next()
            .unwrap_or(op.path.as_str())
            .to_owned();

        let Some(raw_cbor_ref) = block_map.get(record_cid) else {
            warn!(
                peer_did = %peer.did,
                cid = %record_cid_str,
                "record CID not found in CAR block map; skipping",
            );
            continue;
        };

        insert_quarantine(
            pool,
            &record_cid_str,
            &peer.did,
            &nsid,
            raw_cbor_ref,
            sig_status,
        )
        .await?;

        debug!(
            peer_did = %peer.did,
            cid = %record_cid_str,
            nsid = %nsid,
            commit_cid = %commit_cid_str,
            signature_status = sig_status,
            "quarantined federation record",
        );
    }
    Ok(())
}

/// Resolve the commit block from the CAR and verify its signature.
///
/// Returns the `did:key` used for verification on success.
async fn resolve_and_verify_commit_sig(
    peer: &PeerConfig,
    resolver: &Arc<PeerKeyResolver>,
    commit: &proto_blue::repo::CommitEvent,
    block_map: &proto_blue::repo::BlockMap,
    commit_cid_str: &str,
) -> Result<String, FederationError> {
    // Extract the raw commit block bytes.
    let commit_bytes =
        block_map
            .get(&commit.commit)
            .ok_or_else(|| FederationError::RepoFetchFailed {
                did: peer.did.clone(),
                message: "commit CID not found in CAR block map".to_owned(),
            })?;

    // Decode into a SignedCommit.
    let lex_value = proto_blue::lex_cbor::decode(commit_bytes).map_err(|e| {
        FederationError::RepoFetchFailed {
            did: peer.did.clone(),
            message: format!("commit block CBOR decode failed: {e}"),
        }
    })?;
    let signed_commit =
        proto_blue::repo::SignedCommit::from_lex_value(&lex_value).map_err(|e| {
            FederationError::RepoFetchFailed {
                did: peer.did.clone(),
                message: format!("commit block is not a valid SignedCommit: {e}"),
            }
        })?;

    // Resolve the peer's signing key (cache → live fetch).
    let did_key = resolver.resolve(&peer.did).await?;

    // Verify the signature.
    let ok = crate::federation::verify::verify_commit_signature(
        &signed_commit,
        &did_key,
        commit_cid_str,
        &peer.did,
    )?;

    if ok {
        Ok(did_key)
    } else {
        Err(FederationError::SignatureVerifyFailed {
            cid: commit_cid_str.to_owned(),
            did: peer.did.clone(),
        })
    }
}

// ── DB helper ─────────────────────────────────────────────────────────────

/// Insert a record into `federation_quarantine`.
///
/// Uses `ON CONFLICT (cid) DO NOTHING` so replay-on-reconnect is safe.
///
/// The table is new in migration 24 (schema version 25) and the sqlx offline
/// cache does not yet contain a compiled query descriptor for it.
/// We therefore use the untyped `sqlx::query` (no `!` macro) here — the
/// query is parameterised and safe from injection; we just forgo the
/// compile-time column-type checks that `query!` provides.  Once a live
/// `cargo sqlx prepare` pass has been run against the updated schema the
/// query can be promoted to `query!` for the additional type safety.
///
/// # Errors
///
/// Returns [`FederationError::QuarantineWriteFailed`] on any Postgres error.
async fn insert_quarantine(
    pool: &PgPool,
    cid: &str,
    source_did: &str,
    nsid: &str,
    raw_cbor: &[u8],
    signature_status: &str,
) -> Result<(), FederationError> {
    sqlx::query(
        "INSERT INTO federation_quarantine \
            (cid, source_did, nsid, raw_cbor, signature_status) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (cid) DO NOTHING",
    )
    .bind(cid)
    .bind(source_did)
    .bind(nsid)
    .bind(raw_cbor)
    .bind(signature_status)
    .execute(pool)
    .await
    .map_err(FederationError::QuarantineWriteFailed)?;

    Ok(())
}

// ── URL builder ───────────────────────────────────────────────────────────

/// Build the `wss://` URL for `com.atproto.sync.subscribeRepos` against the
/// peer's PDS.
///
/// The `pds_host` field in [`PeerConfig`] must be the bare hostname (no
/// scheme, no path); e.g. `"pds.example.com"`.
fn build_subscribe_url(peer: &PeerConfig) -> String {
    format!(
        "wss://{}/xrpc/com.atproto.sync.subscribeRepos",
        peer.pds_host
    )
}

// ── unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code — rust-quality §7"
)]
mod tests {
    use super::*;
    use crate::federation::{FederationDirection, PeerConfig};

    #[test]
    fn build_subscribe_url_format() {
        let peer = PeerConfig {
            did: "did:plc:peerA".to_owned(),
            pds_host: "pds.example.com".to_owned(),
            direction: FederationDirection::Bidirectional,
        };
        let url = build_subscribe_url(&peer);
        assert_eq!(
            url,
            "wss://pds.example.com/xrpc/com.atproto.sync.subscribeRepos"
        );
    }

    #[test]
    fn polaris_nsid_filter_accepts_matching_paths() {
        let matching = [
            "gay.dollspace.polaris.case/3jui7kd54vh2o",
            "gay.dollspace.polaris.escalation/self",
        ];
        for path in matching {
            let collection = path.split('/').next().unwrap();
            assert!(
                collection.starts_with(POLARIS_NSID_PREFIX),
                "expected {path} to match POLARIS_NSID_PREFIX"
            );
        }
    }

    #[test]
    fn polaris_nsid_filter_rejects_other_paths() {
        let not_matching = [
            "app.bsky.feed.post/abc",
            "com.atproto.sync.subscribeRepos",
            "gay.dollspace.other.record/rkey",
        ];
        for path in not_matching {
            let collection = path.split('/').next().unwrap();
            assert!(
                !collection.starts_with(POLARIS_NSID_PREFIX),
                "expected {path} to NOT match POLARIS_NSID_PREFIX"
            );
        }
    }

    /// Verify the backoff doubling logic and cap.
    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = BACKOFF_INITIAL; // 1s
        b = (b * 2).min(BACKOFF_CAP); // 2s
        assert_eq!(b, Duration::from_secs(2));
        b = (b * 2).min(BACKOFF_CAP); // 4s
        assert_eq!(b, Duration::from_secs(4));
        // Force to cap.
        b = Duration::from_secs(32);
        b = (b * 2).min(BACKOFF_CAP); // 64 → capped at 60
        assert_eq!(b, BACKOFF_CAP);
    }

    /// Verify the cancel-safety property is maintained: if the cancellation
    /// token fires before any pump item arrives, the consume loop returns Ok.
    #[tokio::test]
    async fn consume_loop_exits_on_cancel() {
        use crate::federation::verify::{LabelerServiceFetcher, PeerKeyResolver};
        use std::sync::Arc;

        #[derive(Debug)]
        struct PanicFetcher;
        impl LabelerServiceFetcher for PanicFetcher {
            fn fetch_signing_key<'a>(
                &'a self,
                _peer_did: &'a str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<String, FederationError>> + Send + 'a>,
            > {
                Box::pin(async move { panic!("PanicFetcher should never be called in this test") })
            }
        }

        let peer = PeerConfig {
            did: "did:plc:test".to_owned(),
            pds_host: "pds.test".to_owned(),
            direction: FederationDirection::Bidirectional,
        };
        let resolver = Arc::new(PeerKeyResolver::new(
            Duration::from_secs(3600),
            Box::new(PanicFetcher),
        ));
        let cancel = CancellationToken::new();

        // Fire cancellation immediately.
        cancel.cancel();

        let (_, mut pump_rx) = mpsc::channel::<PumpItem>(1);

        // Pool is unused because we cancel before any DB write.
        // We can't create a pool without a running DB, so we just
        // validate the control flow terminates.
        let _cancel_clone = cancel.clone();
        let result = run_consume_loop(
            &peer,
            // Use a fake pool — we never reach DB operations.
            sqlx::PgPool::connect_lazy("postgres://localhost/nonexistent").unwrap(),
            resolver,
            &cancel,
            &mut pump_rx,
        )
        .await;

        assert!(result.is_ok(), "cancelled consume loop should return Ok");
    }
}
