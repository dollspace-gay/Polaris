//! On-demand `queryLabels` backfill against a single upstream labeler.
//!
//! Polaris's live `subscribeLabels` consumers pick up new labels from
//! the moment they connect onward, but every label emitted *before*
//! that point is invisible to the third-party labels panel — the index
//! starts at the cursor we held when the consumer first ran. For a
//! moderator who opens a subject and expects to see the full label
//! history (including labels emitted years before Polaris was
//! deployed), the live tail isn't enough.
//!
//! This module fills the gap with the same pull-based pattern
//! [`pdsls.dev`](https://pdsls.dev/labels) uses: hit a labeler's
//! `com.atproto.label.queryLabels` XRPC endpoint with the subject DID
//! as both an account-level pattern (`<did>`) and a post-level wildcard
//! (`at://<did>/*`), walk the paginated response, signature-verify
//! every returned label against the same [`UpstreamKeyCache`] the
//! live subscriber uses, and persist each verified label into
//! [`indexed_labels`] via the existing [`super::upstream_labels`]
//! helpers.
//!
//! # Orchestration boundary
//!
//! This module exposes [`backfill_one_labeler`] as the smallest
//! reusable unit — one `(subject_did, labeler_did, labeler_hostname)`
//! pair → one queryLabels walk → an outcome describing what landed
//! in `indexed_labels` and whether the labeler was reachable. The
//! orchestration that decides *which* (subject, labeler) pairs to
//! drive and at what cadence lives in
//! [`crate::ingest::label_backfill_worker`], which pulls work from
//! the durable `label_backfill_queue` table.
//!
//! The case-view handler used to drive a synchronous 300-way fan-out
//! inline; that path was deleted because (a) it ran against the same
//! glibc resolver the live subscribers were saturating with NXDOMAIN
//! attempts and timed out at 60s under contention, and (b) it gave the
//! moderator a one-shot view of "whatever labels the fastest few
//! labelers returned in the deadline window" rather than the full
//! ecosystem-wide history the panel is supposed to surface. The
//! queue + worker pair turns the panel into an eventually-consistent
//! read of `indexed_labels`, which is the architecture the rest of
//! the labeler subsystem already assumed.

use proto_blue::api::generated::com::atproto::label::defs::Label as ProtoLabel;
use proto_blue::syntax::{Datetime as ProtoDatetime, Did as ProtoDid};
use serde::Deserialize;
use sqlx::PgPool;
use tracing::warn;

use crate::ingest::upstream_labels::UpstreamKeyCache;

/// Maximum number of pages to walk per labeler per backfill.
///
/// 200 pages × 250 labels/page = 50,000 labels per labeler per
/// subject. This is functionally unbounded for any real account
/// (a heavily moderated account has tens to low hundreds of labels
/// from any single labeler, not tens of thousands). The cap exists
/// only as a runaway-protection guard against a misbehaving
/// labeler that paginates infinitely; the expected case finishes
/// in 1-2 pages.
const MAX_PAGES_PER_LABELER: usize = 200;

/// Page size requested from each labeler's `queryLabels`. The atproto
/// spec caps at 250.
const QUERY_LABELS_PAGE_SIZE: u32 = 250;

/// Number of times to retry a single page request on connect /
/// transport failure. One retry is enough to absorb a single
/// dropped packet or DNS hiccup without adding meaningful
/// latency to the per-pair budget (the retry fires immediately,
/// no backoff sleep).
const PER_PAGE_RETRIES: usize = 1;

/// Outcome of [`backfill_one_labeler`].
///
/// The worker uses the variant to decide how to transition the queue
/// row: `Success` → `done`, `TransportFailure` → keep `pending` with
/// an exponential `next_attempt_at`, `PermanentFailure` → terminal
/// `permanent_failure` so the worker never retries.
#[derive(Debug)]
pub enum BackfillOutcome {
    /// The labeler responded, we walked pagination to completion (or
    /// the runaway cap), and verified+persisted `labels_persisted`
    /// labels. A labeler that returns an empty list legitimately
    /// counts as success — there is nothing to back-fill and the
    /// queue row should advance to `done` so we don't retry forever.
    Success {
        /// How many `indexed_labels` rows were newly inserted or
        /// upserted.
        labels_persisted: usize,
    },
    /// The labeler was unreachable at the transport layer (DNS
    /// NXDOMAIN, connect refused, TLS handshake failure, etc.).
    /// The worker keeps the row `pending` and schedules a re-attempt.
    /// The string is the joined `source()` chain so an operator can
    /// distinguish "labeler down" from "host network flap".
    TransportFailure {
        /// Human-readable cause chain — surfaced verbatim in
        /// `label_backfill_queue.last_error`.
        cause: String,
    },
    /// The labeler returned a non-2xx HTTP status. This is treated
    /// as a terminal failure because:
    ///   * 404 = the labeler doesn't implement queryLabels (lots of
    ///     personal labelers don't);
    ///   * 4xx more broadly = our request is malformed; retrying
    ///     won't fix that;
    ///   * 5xx = the labeler is broken on their end; we'd rather not
    ///     pound on it for the next 24h. The supervisor's dormancy
    ///     path covers the longer-term retry; the per-pair queue
    ///     row stops here.
    PermanentFailure {
        /// Best-effort summary of the failure (status code, response
        /// body excerpt, etc.) for `label_backfill_queue.last_error`.
        reason: String,
    },
}

/// Query a single labeler's `queryLabels` endpoint for both the
/// account-level pattern and the `at://<did>/*` post-level wildcard,
/// walking pagination until the labeler returns no cursor (or
/// [`MAX_PAGES_PER_LABELER`] is hit, whichever comes first).
///
/// Every verified label is persisted into `indexed_labels` via the
/// existing [`crate::ingest::upstream_labels::persist_to_indexed_labels`]
/// helper, so the read side ([`network_context::fetch_all_labels_for_subject`])
/// picks them up on the next render.
///
/// The function never panics on a labeler-side fault: malformed JSON,
/// unverifiable signatures, and bad timestamps are logged at WARN and
/// the next label is tried. The outcome reflects the *labeler*-level
/// reachability, not per-label fidelity.
pub async fn backfill_one_labeler(
    pool: &PgPool,
    key_cache: &UpstreamKeyCache,
    http: &reqwest::Client,
    subject_did: &str,
    labeler_did: &str,
    labeler_hostname: &str,
) -> BackfillOutcome {
    let post_pattern = format!("at://{subject_did}/*");
    let url = format!("https://{labeler_hostname}/xrpc/com.atproto.label.queryLabels");
    let mut cursor: Option<String> = None;
    let mut persisted = 0_usize;
    let mut saw_any_page = false;

    for page in 0..MAX_PAGES_PER_LABELER {
        // Build the query the way the lexicon expects: repeated
        // `uriPatterns` query params, optional cursor, optional
        // sources filter to scope the result to this labeler's own
        // emissions (defensive — some labelers proxy other labelers'
        // labels and we want the fan-out to remain attributable per
        // row).
        let mut query: Vec<(&str, String)> = Vec::with_capacity(6);
        query.push(("uriPatterns", subject_did.to_owned()));
        query.push(("uriPatterns", post_pattern.clone()));
        query.push(("sources", labeler_did.to_owned()));
        query.push(("limit", QUERY_LABELS_PAGE_SIZE.to_string()));
        if let Some(c) = cursor.as_ref() {
            query.push(("cursor", c.clone()));
        }

        let page_result = request_one_page(
            http,
            &url,
            &query,
            subject_did,
            labeler_did,
            labeler_hostname,
            page,
        )
        .await;
        let body = match page_result {
            PageOutcome::Body(b) => {
                saw_any_page = true;
                b
            }
            PageOutcome::TerminalNon2xx(reason) => {
                // First page returning non-2xx is a terminal failure for
                // the whole pair; subsequent pages returning non-2xx
                // means we already persisted something — in that case
                // we still count this as a successful run so the queue
                // doesn't get stuck retrying. The supervisor-level
                // dormancy path handles the longer-term back-off via
                // the WebSocket consumer.
                if saw_any_page {
                    return BackfillOutcome::Success {
                        labels_persisted: persisted,
                    };
                }
                return BackfillOutcome::PermanentFailure { reason };
            }
            PageOutcome::TransportFailure(cause) => {
                if saw_any_page {
                    // Mid-walk transport flap — keep what we have, log
                    // the partial completion as a success so we don't
                    // re-walk pages we already persisted.
                    return BackfillOutcome::Success {
                        labels_persisted: persisted,
                    };
                }
                return BackfillOutcome::TransportFailure { cause };
            }
        };

        for label in &body.labels {
            match verify_and_persist(pool, key_cache, label).await {
                Ok(true) => persisted = persisted.saturating_add(1),
                Ok(false) => {}
                Err(err) => warn!(
                    target: "label_backfill",
                    subject_did,
                    labeler = %labeler_did,
                    error = %err,
                    "label verify-or-persist failed",
                ),
            }
        }
        cursor.clone_from(&body.cursor);
        if cursor.is_none() || body.labels.is_empty() {
            break;
        }
    }

    BackfillOutcome::Success {
        labels_persisted: persisted,
    }
}

/// Per-page outcome shape used by [`request_one_page`]. Keeps the
/// caller's match arms exhaustive without resorting to nested
/// `Result<Result<_,_>,_>`.
enum PageOutcome {
    /// Successful 2xx + JSON parse.
    Body(QueryLabelsResponse),
    /// Non-2xx response — terminal for the page walk.
    TerminalNon2xx(String),
    /// Connect / TLS / DNS / read failure after exhausting retries.
    TransportFailure(String),
}

/// Issue one `queryLabels` page request with bounded retries on
/// transport failure. Per-attempt errors are logged at WARN with the
/// full reqwest source chain so an operator can distinguish "labeler
/// down" from "host network flap".
async fn request_one_page(
    http: &reqwest::Client,
    url: &str,
    query: &[(&str, String)],
    subject_did: &str,
    labeler_did: &str,
    labeler_hostname: &str,
    page: usize,
) -> PageOutcome {
    for attempt in 0..=PER_PAGE_RETRIES {
        let resp = http.get(url).query(query).send().await;
        match resp {
            Ok(r) if r.status().is_success() => {
                return match r.json::<QueryLabelsResponse>().await {
                    Ok(body) => PageOutcome::Body(body),
                    Err(err) => {
                        warn!(
                            target: "label_backfill",
                            subject_did,
                            labeler = %labeler_did,
                            hostname = %labeler_hostname,
                            page,
                            error = %err,
                            "queryLabels JSON parse failed",
                        );
                        PageOutcome::TerminalNon2xx(format!("json parse: {err}"))
                    }
                };
            }
            Ok(r) => {
                let status = r.status();
                warn!(
                    target: "label_backfill",
                    subject_did,
                    labeler = %labeler_did,
                    hostname = %labeler_hostname,
                    page,
                    status = %status,
                    "queryLabels returned non-2xx",
                );
                return PageOutcome::TerminalNon2xx(format!("HTTP {status}"));
            }
            Err(err) => {
                if attempt < PER_PAGE_RETRIES {
                    warn!(
                        target: "label_backfill",
                        subject_did,
                        labeler = %labeler_did,
                        hostname = %labeler_hostname,
                        page,
                        attempt,
                        error = %err,
                        cause = %reqwest_error_chain(&err),
                        "queryLabels GET failed; retrying",
                    );
                    continue;
                }
                let cause = reqwest_error_chain(&err);
                warn!(
                    target: "label_backfill",
                    subject_did,
                    labeler = %labeler_did,
                    hostname = %labeler_hostname,
                    page,
                    attempts = attempt + 1,
                    error = %err,
                    cause = %cause,
                    "queryLabels GET failed; retries exhausted",
                );
                return PageOutcome::TransportFailure(cause);
            }
        }
    }
    // Belt-and-braces — the loop body always returns; the compiler
    // can't prove that statically without the trailing branch.
    PageOutcome::TransportFailure("retry loop exited unexpectedly".to_owned())
}

/// Walk the `source()` chain of a `reqwest::Error` and return the
/// full cause chain joined by ` → `. Used when the outer Display
/// (`"error sending request"`) hides the actual failure mode
/// (DNS NXDOMAIN, TLS handshake, connect refused, etc.). Without
/// this an operator looking at the log sees only "request failed"
/// across hundreds of labelers and can't distinguish a real network
/// issue from a misbehaving labeler endpoint.
fn reqwest_error_chain(err: &reqwest::Error) -> String {
    let mut out = String::new();
    let mut current: Option<&dyn std::error::Error> = std::error::Error::source(err);
    while let Some(cause) = current {
        if !out.is_empty() {
            out.push_str(" → ");
        }
        out.push_str(&cause.to_string());
        current = cause.source();
    }
    if out.is_empty() {
        out.push_str("(no source)");
    }
    out
}

/// On-the-wire label shape returned by `com.atproto.label.queryLabels`.
///
/// Mirrors the lexicon's `QueryLabelsResponse` but is decoded via
/// plain `serde_json` so the backfill module does not depend on the
/// proto-blue typed XRPC client (which would pull in a heavier
/// dependency for just this read). The fields we care about are a
/// strict subset of the spec.
#[derive(Debug, Deserialize)]
struct QueryLabelsResponse {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    labels: Vec<JsonLabel>,
}

/// One label entry as returned by `queryLabels`. The signature is
/// wrapped as `{"$bytes": "<base64>"}` per the atproto JSON binding
/// convention; [`JsonBytes`] handles the decode.
#[derive(Debug, Deserialize)]
struct JsonLabel {
    #[serde(default)]
    ver: Option<i64>,
    src: String,
    uri: String,
    #[serde(default)]
    cid: Option<String>,
    val: String,
    #[serde(default)]
    neg: Option<bool>,
    cts: String,
    #[serde(default)]
    exp: Option<String>,
    #[serde(default)]
    sig: Option<JsonBytes>,
}

/// atproto JSON convention for raw bytes: `{"$bytes": "<base64>"}`.
/// Base64 is unpadded URL-safe per RFC 4648 §5. proto-blue uses the
/// `base64` crate's `URL_SAFE_NO_PAD` constant; we match that exactly
/// so labels backfilled here verify under the same key the live
/// subscriber would have accepted.
#[derive(Debug, Deserialize)]
struct JsonBytes {
    #[serde(rename = "$bytes")]
    b64: String,
}

impl JsonBytes {
    fn decode(&self) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine as _;
        // atproto JSON encodes bytes as standard base64 (with padding)
        // per the spec's "jsonCBOR" mapping (§Data Model). The
        // padding is sometimes omitted in practice, so accept both
        // shapes via the lenient `STANDARD_NO_PAD` engine, then fall
        // back to the strict `STANDARD` engine if that rejects.
        base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(self.b64.trim_end_matches('='))
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&self.b64))
    }
}

/// Verify a backfilled label's signature against its labeler's
/// cached signing key (via [`UpstreamKeyCache`]) and persist it on
/// success. Returns `true` if a row was actually inserted /
/// upserted; `false` if the row was skipped (unsigned, malformed
/// timestamps, etc.).
async fn verify_and_persist(
    pool: &PgPool,
    key_cache: &UpstreamKeyCache,
    label: &JsonLabel,
) -> Result<bool, BackfillVerifyError> {
    let Some(sig_field) = label.sig.as_ref() else {
        return Ok(false);
    };
    let sig_bytes = sig_field
        .decode()
        .map_err(|e| BackfillVerifyError::SigDecode(e.to_string()))?;

    let signing_did = key_cache
        .get_or_fetch(&label.src)
        .await
        .map_err(|e| BackfillVerifyError::KeyLookup(e.to_string()))?;

    // Build the typed ProtoLabel that the canonical encoder expects.
    let proto_label = ProtoLabel {
        ver: label.ver,
        src: ProtoDid::new(&label.src).map_err(|e| BackfillVerifyError::Src(e.to_string()))?,
        uri: label.uri.clone(),
        cid: label.cid.clone(),
        val: label.val.clone(),
        neg: label.neg,
        cts: ProtoDatetime::new(&label.cts).map_err(|e| BackfillVerifyError::Cts(e.to_string()))?,
        exp: label
            .exp
            .as_deref()
            .map(ProtoDatetime::new)
            .transpose()
            .map_err(|e| BackfillVerifyError::Exp(e.to_string()))?,
        sig: None, // explicitly None for the canonical pre-signature encode
    };
    let cbor = crate::ingest::upstream_labels::encode_label_canonical(&proto_label)
        .map_err(|e| BackfillVerifyError::CanonicalEncode(e.to_string()))?;
    let ok = proto_blue::crypto::verify_signature(&signing_did, &cbor, &sig_bytes, false)
        .map_err(|e| BackfillVerifyError::Verify(e.to_string()))?;
    if !ok {
        return Err(BackfillVerifyError::BadSignature);
    }

    // Persist. We use seq=0 here — the queryLabels response does not
    // carry a sequence number, and the live subscriber's `seq` values
    // are millions, so a future live frame from the same labeler
    // will always win the `seq <= EXCLUDED.seq` ON CONFLICT guard
    // and refresh the row.
    crate::ingest::upstream_labels::persist_to_indexed_labels(pool, &proto_label, &sig_bytes, 0)
        .await
        .map_err(|e| BackfillVerifyError::Persist(e.to_string()))?;
    Ok(true)
}

#[derive(Debug, thiserror::Error)]
enum BackfillVerifyError {
    #[error("sig base64 decode: {0}")]
    SigDecode(String),
    #[error("key lookup: {0}")]
    KeyLookup(String),
    #[error("src DID: {0}")]
    Src(String),
    #[error("cts: {0}")]
    Cts(String),
    #[error("exp: {0}")]
    Exp(String),
    #[error("canonical encode: {0}")]
    CanonicalEncode(String),
    #[error("verify: {0}")]
    Verify(String),
    #[error("bad signature")]
    BadSignature,
    #[error("persist: {0}")]
    Persist(String),
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code — rust-quality §7"
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_bytes_decodes_unpadded_base64() {
        // The wire shape we observed from `mod.bsky.app`:
        //   "sig":{"$bytes":"aWWjuVN4lVZtov/oYHmmvgknUbE3SKmiMr2c+zN0RT45BFYFRk5jHaqrlZygIOCOz24NXm3dTIts/EwNRYmW5w"}
        // Unpadded standard base64 (`+/` alphabet, no `=` tail).
        let v: JsonBytes = serde_json::from_value(json!({
            "$bytes": "aWWjuVN4lVZtov/oYHmmvgknUbE3SKmiMr2c+zN0RT45BFYFRk5jHaqrlZygIOCOz24NXm3dTIts/EwNRYmW5w"
        }))
        .unwrap();
        let raw = v.decode().expect("decode succeeds");
        // K256 ECDSA signatures are 64 bytes (compact R || S).
        assert_eq!(raw.len(), 64, "got {} bytes", raw.len());
    }

    #[test]
    fn json_bytes_also_accepts_padded_base64() {
        // Some implementations include the padding; we accept both.
        let v: JsonBytes = serde_json::from_value(json!({
            "$bytes": "aGVsbG8="
        }))
        .unwrap();
        assert_eq!(v.decode().unwrap(), b"hello");
    }

    #[test]
    fn query_labels_response_parses_real_shape() {
        // Captured live from `mod.bsky.app/xrpc/com.atproto.label.queryLabels`
        // for dollspace.gay's posts. The fixture is the actual wire
        // body trimmed to one entry; the parser must accept it
        // verbatim.
        let body = json!({
            "cursor": "14933150",
            "labels": [{
                "ver": 1,
                "src": "did:plc:ar7c4by46qjdydhdevvrndac",
                "uri": "at://did:plc:dzvxvsiy3maw4iarpvizsj67/app.bsky.feed.post/3m2banebedc2j",
                "cid": "bafyreidfc6cmkni6neb5mvduucz7iwlkaei5ypvjmvlwvypu4nfvymgozq",
                "val": "rude",
                "cts": "2025-10-03T17:45:42.231Z",
                "sig": {"$bytes": "aWWjuVN4lVZtov/oYHmmvgknUbE3SKmiMr2c+zN0RT45BFYFRk5jHaqrlZygIOCOz24NXm3dTIts/EwNRYmW5w"}
            }]
        });
        let parsed: QueryLabelsResponse = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.cursor.as_deref(), Some("14933150"));
        assert_eq!(parsed.labels.len(), 1);
        let l = &parsed.labels[0];
        assert_eq!(l.src, "did:plc:ar7c4by46qjdydhdevvrndac");
        assert_eq!(l.val, "rude");
        assert_eq!(l.ver, Some(1));
        assert!(l.sig.is_some());
        assert_eq!(l.neg, None);
    }

    #[test]
    fn query_labels_response_accepts_empty_cursor() {
        let body = json!({"labels": []});
        let parsed: QueryLabelsResponse = serde_json::from_value(body).unwrap();
        assert!(parsed.cursor.is_none());
        assert!(parsed.labels.is_empty());
    }

    #[test]
    fn outcome_success_persists_count() {
        let o = BackfillOutcome::Success {
            labels_persisted: 3,
        };
        match o {
            BackfillOutcome::Success { labels_persisted } => assert_eq!(labels_persisted, 3),
            BackfillOutcome::TransportFailure { .. } | BackfillOutcome::PermanentFailure { .. } => {
                panic!("expected Success variant")
            }
        }
    }
}
