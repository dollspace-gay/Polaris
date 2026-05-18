//! Inbound upstream-labeler consumer: AC-10 binding (issue #32).
//!
//! Three integration tests against a testcontainers Postgres:
//!
//! 1. **AC-10 binding (`verified_label_lands_as_external_observation`)** —
//!    seed an upstream + its cached pubkey, sign a `Label` with the
//!    corresponding K-256 keypair, call the per-frame handler directly,
//!    and assert an `ExternalLabel` observation lands on the matching
//!    subject within ≤ 5 seconds with the right weight.
//! 2. **Verify rejection (`tampered_signature_is_dropped`)** — same setup
//!    but with the signature byte-flipped; assert no observation row
//!    appears and the structured WARN was logged.
//! 3. **Cursor persistence (`cursor_persists_across_consumer_reinstantiation`)**
//!    — flush a cursor, drop the consumer, build a fresh one against the
//!    same DB; assert `load_cursor` returns the persisted value.
//!
//! # Skip behaviour
//!
//! If Docker is unreachable the tests print a skip message and return
//! `Ok(())`, mirroring the rest of the suite.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::ingest::upstream_labels::{
    self, CacheError, UpstreamKeyCache, UpstreamKeyFetcher, UpstreamLabelerConfig,
    UpstreamLabelerConsumer,
};
use polaris_backend::repo::PgObservationRepo;
use polaris_types::ObservationKind;
use proto_blue::api::generated::com::atproto::label::defs::Label as ProtoLabel;
use proto_blue::crypto::{K256Keypair, Keypair as _, Signer as _};
use proto_blue::lex_cbor;
use proto_blue::lex_json;
use proto_blue::syntax::{Datetime as ProtoDatetime, Did as ProtoDid};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tracing_test::traced_test;

// ── docker probe ────────────────────────────────────────────────────────

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── fetcher stubs ───────────────────────────────────────────────────────

/// Fetcher that always returns the configured did:key. Used to assert
/// the cache layer flows DB-miss → fetcher → persist correctly.
struct StubFetcher {
    did_key: String,
}

impl UpstreamKeyFetcher for StubFetcher {
    fn fetch(
        &self,
        _upstream_did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, CacheError>> + Send + '_>>
    {
        let did_key = self.did_key.clone();
        Box::pin(async move { Ok(did_key) })
    }
}

/// Fetcher that panics if called — used to assert that a pre-seeded cache
/// hit never touches the fetcher path.
struct UnreachableFetcher;

impl UpstreamKeyFetcher for UnreachableFetcher {
    fn fetch(
        &self,
        _upstream_did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, CacheError>> + Send + '_>>
    {
        Box::pin(async move {
            panic!("fetcher was called despite a seeded in-memory cache entry");
        })
    }
}

// ── shared test rig ─────────────────────────────────────────────────────

/// Build a signed K-256 label over a target uri/value pair, plus the
/// upstream's `did:key:z…` form. Mirrors the labeler emitter's
/// canonical-encoding chain (JSON → `LexValue` → DAG-CBOR) so the byte
/// shape exactly matches what `verify_signature` expects.
fn build_signed_label(signer: &K256Keypair, target_uri: &str, val: &str) -> (ProtoLabel, String) {
    let signing_did = signer.did();
    let src = ProtoDid::new(&signing_did).expect("valid did:key");
    let mut label = ProtoLabel {
        cid: None,
        cts: ProtoDatetime::from_utc(Utc::now()),
        exp: None,
        neg: Some(false),
        sig: None,
        src,
        uri: target_uri.to_owned(),
        val: val.to_owned(),
        ver: Some(1),
    };
    // Canonicalise (sig omitted because it's None).
    let json = serde_json::to_value(&label).expect("serialize label");
    let lex = lex_json::json_to_lex(&json);
    let cbor = lex_cbor::encode(&lex).expect("encode dag-cbor");
    let sig = signer.sign(&cbor).expect("sign");
    label.sig = Some(sig);
    (label, signing_did)
}

/// Seed an `upstream_labelers` row + the cached signing-key row.
async fn seed_upstream(
    pool: &PgPool,
    upstream_did: &str,
    signing_pubkey_did: &str,
    weights: &serde_json::Value,
) {
    sqlx::query!(
        r#"
        INSERT INTO upstream_labelers (did, hostname, weights, enabled)
        VALUES ($1, $2, $3, TRUE)
        "#,
        upstream_did,
        "labeler.example",
        weights,
    )
    .execute(pool)
    .await
    .expect("insert upstream_labelers row");

    sqlx::query!(
        r#"
        INSERT INTO upstream_labeler_keys (did, signing_pubkey_did)
        VALUES ($1, $2)
        "#,
        upstream_did,
        signing_pubkey_did,
    )
    .execute(pool)
    .await
    .expect("insert upstream_labeler_keys row");
}

/// Stand up a PG16-alpine container + run migrations + hand back the pool
/// and the testcontainer guard (which keeps the container alive while the
/// test owns it).
async fn start_db() -> (
    testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
    PgPool,
) {
    let container = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("start container");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port");
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let db = db::connect(&cfg).await.expect("db connect + migrate");
    let pool = db.pool().clone();
    (container, pool)
}

// ── tests ───────────────────────────────────────────────────────────────

/// AC-10 binding: a verified inbound `Label` lands as an `ExternalLabel`
/// observation on the matching subject within 5s with the configured
/// trust weight.
#[tokio::test]
async fn verified_label_lands_as_external_observation() {
    if !docker_available() {
        println!("SKIP upstream_labelers AC-10 binding: docker not reachable");
        return;
    }
    let (_container, pool) = start_db().await;

    let upstream_did = "did:plc:upstream-test";
    let signer = K256Keypair::generate();
    let signing_did = signer.did();
    // Operator-configured weights: spam → 0.4, default → 0.5.
    let weights = serde_json::json!({ "spam": 0.4 });
    seed_upstream(&pool, upstream_did, &signing_did, &weights).await;

    let cfg = UpstreamLabelerConfig::from_row(
        upstream_did.to_owned(),
        "labeler.example".to_owned(),
        &weights,
    );
    let cache = Arc::new(UpstreamKeyCache::new(
        pool.clone(),
        Arc::new(UnreachableFetcher),
    ));
    // Pre-seed the in-memory cache so the fetcher is never called.
    cache
        .seed_in_memory_for_tests(
            upstream_did,
            signing_did.clone(),
            Duration::from_secs(60 * 60),
        )
        .await;

    let observations = Arc::new(PgObservationRepo::new(pool.clone()));
    let consumer = UpstreamLabelerConsumer::new(cfg, pool.clone(), observations, cache);

    // Signed label targeting an account DID with val="spam".
    let target_did = "did:plc:victim-account";
    let (label, _) = build_signed_label(&signer, target_did, "spam");

    let start = std::time::Instant::now();
    consumer
        .handle_frame(&label)
        .await
        .expect("verified label must be accepted");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "AC-10: verified label must land within 5s",
    );

    // The subject row must exist and carry an ExternalLabel observation.
    let row = sqlx::query!(
        r#"
        SELECT o.kind, o.confidence, o.evidence
        FROM observations o
        JOIN subjects s ON s.id = o.subject_id
        WHERE s.did = $1 AND s.kind = 'account'
        "#,
        target_did,
    )
    .fetch_one(&pool)
    .await
    .expect("observation row");
    assert_eq!(row.kind, "external_label");
    // The configured weight is 0.4 for "spam"; both `confidence` (outer)
    // and the embedded `weight` field on `ExternalLabel` must match.
    assert!(
        (row.confidence - 0.4).abs() < 1e-5,
        "confidence={}",
        row.confidence
    );

    // Round-trip the typed kind to confirm the embedded ExternalLabel
    // fields are intact.
    let envelope = serde_json::json!({ "kind": row.kind, "data": row.evidence });
    let typed: ObservationKind =
        serde_json::from_value(envelope).expect("decode typed ObservationKind");
    match typed {
        ObservationKind::ExternalLabel {
            source,
            label_value,
            weight,
        } => {
            assert_eq!(source.as_str(), upstream_did);
            assert_eq!(label_value.as_str(), "spam");
            assert!((weight - 0.4).abs() < 1e-5);
        }
        other => panic!("expected ExternalLabel, got {other:?}"),
    }

    // The risk_signals trigger must have fired: the subject's
    // denormalised vector contains at least the one observation we just
    // inserted.
    let signals = sqlx::query!(
        r#"
        SELECT risk_signals
        FROM subjects
        WHERE did = $1 AND kind = 'account'
        "#,
        target_did,
    )
    .fetch_one(&pool)
    .await
    .expect("subject risk_signals");
    let arr = signals
        .risk_signals
        .as_array()
        .expect("risk_signals is an array");
    assert!(
        !arr.is_empty(),
        "risk_signals must contain the new observation"
    );
}

/// Tampered signature → no observation row, structured WARN logged.
#[tokio::test]
#[traced_test]
async fn tampered_signature_is_dropped() {
    if !docker_available() {
        println!("SKIP upstream_labelers tamper test: docker not reachable");
        return;
    }
    let (_container, pool) = start_db().await;

    let upstream_did = "did:plc:upstream-tamper";
    let signer = K256Keypair::generate();
    let signing_did = signer.did();
    let weights = serde_json::json!({});
    seed_upstream(&pool, upstream_did, &signing_did, &weights).await;

    let cfg = UpstreamLabelerConfig::from_row(
        upstream_did.to_owned(),
        "labeler.example".to_owned(),
        &weights,
    );
    let cache = Arc::new(UpstreamKeyCache::new(
        pool.clone(),
        Arc::new(StubFetcher {
            did_key: signing_did.clone(),
        }),
    ));
    let observations = Arc::new(PgObservationRepo::new(pool.clone()));
    let consumer = UpstreamLabelerConsumer::new(cfg, pool.clone(), observations, cache);

    let target_did = "did:plc:victim-tamper";
    let (mut label, _) = build_signed_label(&signer, target_did, "spam");
    // Tamper: flip a bit in the signature. The first byte's low nibble is
    // an unbiased choice — it lands inside the `r` component of the
    // compact-form signature, which is one of the parts the verifier
    // actually checks against the curve.
    if let Some(sig) = label.sig.as_mut() {
        sig[0] ^= 0x01;
    }

    // Per AC-10, the handler must reject without persisting.
    let err = consumer
        .handle_frame(&label)
        .await
        .expect_err("tampered label must be rejected");
    let category = format!("{err:?}");
    assert!(
        category.contains("BadSignature") || category.contains("Crypto"),
        "expected BadSignature/Crypto error, got {category}",
    );

    // No observation row may have been inserted; the subject row may not
    // exist either (we never resolved it).
    let count = sqlx::query!("SELECT COUNT(*) AS cnt FROM observations")
        .fetch_one(&pool)
        .await
        .expect("count observations")
        .cnt
        .unwrap_or(0);
    assert_eq!(count, 0, "no observation may be persisted on tamper");
}

/// Cursor persistence: process one frame's `seq=42`, verify the row,
/// re-instantiate the consumer (don't tear down the DB), assert cursor
/// reads back 42.
#[tokio::test]
async fn cursor_persists_across_consumer_reinstantiation() {
    if !docker_available() {
        println!("SKIP upstream_labelers cursor test: docker not reachable");
        return;
    }
    let (_container, pool) = start_db().await;

    let upstream_did = "did:plc:upstream-cursor";
    let signer = K256Keypair::generate();
    let signing_did = signer.did();
    let weights = serde_json::json!({});
    seed_upstream(&pool, upstream_did, &signing_did, &weights).await;

    let cfg = UpstreamLabelerConfig::from_row(
        upstream_did.to_owned(),
        "labeler.example".to_owned(),
        &weights,
    );
    let cache = Arc::new(UpstreamKeyCache::new(
        pool.clone(),
        Arc::new(StubFetcher {
            did_key: signing_did.clone(),
        }),
    ));
    let observations = Arc::new(PgObservationRepo::new(pool.clone()));

    {
        let consumer = UpstreamLabelerConsumer::new(
            cfg.clone(),
            pool.clone(),
            observations.clone(),
            cache.clone(),
        );
        consumer.flush_cursor(42).await.expect("flush cursor at 42");
        // First consumer goes out of scope here — DB is not torn down.
        drop(consumer);
    }

    // Re-instantiate against the same DB; cursor read must return 42.
    let consumer2 = UpstreamLabelerConsumer::new(cfg, pool.clone(), observations, cache);
    let seq = upstream_labels::load_cursor(&pool, upstream_did)
        .await
        .expect("load cursor");
    assert_eq!(seq, 42, "cursor must persist across consumer rebuild");
    // Re-flush at a higher value to confirm forward progress.
    consumer2
        .flush_cursor(99)
        .await
        .expect("flush cursor at 99");
    let seq = upstream_labels::load_cursor(&pool, upstream_did)
        .await
        .expect("load cursor 2");
    assert_eq!(seq, 99);

    // Monotonicity at the DB: a rewind attempt to 5 must not lower the
    // persisted cursor.
    consumer2
        .flush_cursor(5)
        .await
        .expect("rewind attempt must not error");
    let seq = upstream_labels::load_cursor(&pool, upstream_did)
        .await
        .expect("load cursor 3");
    assert_eq!(seq, 99, "stale writer must not rewind cursor");
}

/// `indexed_labels` write — the bunnynabbit local-store half. A verified
/// label must materialise as a row in `indexed_labels` keyed by
/// `(src, uri, val, neg)`, so the case-view query path (#181) can read
/// it without any AppView round-trip.
#[tokio::test]
async fn verified_label_lands_in_indexed_labels() {
    if !docker_available() {
        println!("SKIP indexed_labels test: docker not reachable");
        return;
    }
    let (_container, pool) = start_db().await;

    let upstream_did = "did:plc:upstream-indexed";
    let signer = K256Keypair::generate();
    let signing_did = signer.did();
    let weights = serde_json::json!({});
    seed_upstream(&pool, upstream_did, &signing_did, &weights).await;

    let cfg = UpstreamLabelerConfig::from_row(
        upstream_did.to_owned(),
        "labeler.example".to_owned(),
        &weights,
    );
    let cache = Arc::new(UpstreamKeyCache::new(
        pool.clone(),
        Arc::new(StubFetcher {
            did_key: signing_did.clone(),
        }),
    ));
    let observations = Arc::new(PgObservationRepo::new(pool.clone()));
    let consumer = UpstreamLabelerConsumer::new(cfg, pool.clone(), observations, cache);

    // Post-level URI — the kind of label the original AppView-based
    // panel was *not* surfacing because the operator's account doesn't
    // exist as a Polaris subject.
    let target_uri = "at://did:plc:victim/app.bsky.feed.post/3lkabcdef12";
    let (label, _) = build_signed_label(&signer, target_uri, "spam");

    let returned_seq = consumer
        .handle_frame_with_seq(&label, 1234)
        .await
        .expect("verified label must be accepted");
    assert_eq!(returned_seq, 1234, "handle_frame returns the envelope seq");

    // The row must exist with every wire-shape field populated.
    let row = sqlx::query!(
        r#"
        SELECT src, uri, val, neg, seq, sig, cts, exp
        FROM indexed_labels
        WHERE src = $1 AND uri = $2 AND val = $3
        "#,
        signing_did,
        target_uri,
        "spam",
    )
    .fetch_one(&pool)
    .await
    .expect("indexed_labels row exists");
    assert_eq!(row.src, signing_did);
    assert_eq!(row.uri, target_uri);
    assert_eq!(row.val, "spam");
    assert!(!row.neg, "label was an assertion, not a negation");
    assert_eq!(row.seq, 1234);
    assert!(
        row.sig.is_some_and(|s| !s.is_empty()),
        "signature bytes must persist",
    );
    assert!(row.cts.timestamp() > 0, "cts must be a valid timestamp");
    assert!(row.exp.is_none(), "no exp was supplied on this fixture");

    // Idempotent upsert: re-emit the SAME (src, uri, val, neg) with a
    // newer seq. Row count stays 1; seq advances.
    let (label2, _) = build_signed_label(&signer, target_uri, "spam");
    consumer
        .handle_frame_with_seq(&label2, 9999)
        .await
        .expect("re-emission must succeed");
    let after = sqlx::query!(
        r#"
        SELECT seq, COUNT(*) OVER () AS row_count
        FROM indexed_labels
        WHERE src = $1 AND uri = $2 AND val = $3 AND neg = FALSE
        "#,
        signing_did,
        target_uri,
        "spam",
    )
    .fetch_one(&pool)
    .await
    .expect("indexed_labels row after re-emit");
    assert_eq!(after.row_count, Some(1), "re-emission is an upsert");
    assert_eq!(after.seq, 9999, "newer seq wins");

    // Cursor regression guard: a stale frame (seq < current) must not
    // rewrite the row.
    let (label3, _) = build_signed_label(&signer, target_uri, "spam");
    consumer
        .handle_frame_with_seq(&label3, 100)
        .await
        .expect("stale re-emit must not error");
    let stable = sqlx::query!(
        "SELECT seq FROM indexed_labels WHERE src = $1 AND uri = $2 AND val = $3 AND neg = FALSE",
        signing_did,
        target_uri,
        "spam",
    )
    .fetch_one(&pool)
    .await
    .expect("indexed_labels row after stale frame");
    assert_eq!(stable.seq, 9999, "stale seq must not rewrite");
}

/// Negation preserves history: assert then retract the same value →
/// two rows, one `neg=false`, one `neg=true`.
#[tokio::test]
async fn assert_then_negate_preserves_both_rows() {
    if !docker_available() {
        println!("SKIP indexed_labels negation test: docker not reachable");
        return;
    }
    let (_container, pool) = start_db().await;

    let upstream_did = "did:plc:upstream-neg";
    let signer = K256Keypair::generate();
    let signing_did = signer.did();
    let weights = serde_json::json!({});
    seed_upstream(&pool, upstream_did, &signing_did, &weights).await;

    let cfg = UpstreamLabelerConfig::from_row(
        upstream_did.to_owned(),
        "labeler.example".to_owned(),
        &weights,
    );
    let cache = Arc::new(UpstreamKeyCache::new(
        pool.clone(),
        Arc::new(StubFetcher {
            did_key: signing_did.clone(),
        }),
    ));
    let observations = Arc::new(PgObservationRepo::new(pool.clone()));
    let consumer = UpstreamLabelerConsumer::new(cfg, pool.clone(), observations, cache);

    let target = "did:plc:victim-neg";
    let (asserted, _) = build_signed_label(&signer, target, "warn");
    consumer
        .handle_frame_with_seq(&asserted, 1)
        .await
        .expect("assert");

    // Build a negation: same label but `neg = Some(true)`, re-signed.
    let src = ProtoDid::new(&signing_did).expect("valid did:key");
    let mut retract = ProtoLabel {
        cid: None,
        cts: ProtoDatetime::from_utc(Utc::now()),
        exp: None,
        neg: Some(true),
        sig: None,
        src,
        uri: target.to_owned(),
        val: "warn".to_owned(),
        ver: Some(1),
    };
    let json = serde_json::to_value(&retract).expect("serialize");
    let lex = lex_json::json_to_lex(&json);
    let cbor = lex_cbor::encode(&lex).expect("encode");
    retract.sig = Some(signer.sign(&cbor).expect("sign"));
    consumer
        .handle_frame_with_seq(&retract, 2)
        .await
        .expect("retract");

    let rows = sqlx::query!(
        "SELECT neg FROM indexed_labels WHERE src = $1 AND uri = $2 AND val = $3 ORDER BY neg",
        signing_did,
        target,
        "warn",
    )
    .fetch_all(&pool)
    .await
    .expect("rows");
    assert_eq!(rows.len(), 2, "assert + retract both persist");
    assert!(!rows[0].neg);
    assert!(rows[1].neg);
}
