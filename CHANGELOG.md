# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Add labeler service hosting and v1 hardening (M4) (#6)
- Expand Polaris beyond v1 (M5+) (#41)
- Add wellness instrumentation, specialty routing, and appeals (M3) (#5)
- Add pattern engine and pattern dashboard (M2) (#4)
- Add ATProto firehose ingest and incident aggregation (M1) (#3)
- Establish workspace and skeleton (M0) (#2)

### Fixed
- Fix #29 cloud-kms serde tag mismatch (variant produces cloud-kms; code expects cloud-kms-oracle) (#63)
- Fix bad_request_carries_static_message test in api/error.rs (#55)
- Refine xtask hardcoded_mutating_route rule to allow PolarisApiClient gateway (#53)
- Resolve proto-blue 0.3.1 MSRV blocker (1.88 features under declared 1.85) (#50)

### Changed
- Add reporter reputation scoring and false-report weighting in pattern engine (#37)
- Iterate Polaris tech architecture around proto-blue SDK (#1)
- Add hardware-token (PKCS#11 / FIDO2 HSM) SigningKey impl with attended-signing UX (#49)
- Add TPM-sealed signing key SigningKey impl (#48)
- Add richer cross-labeler trust model with per-source per-category time-decay weights (#47)
- Add Ozone-to-Polaris migration tooling (#46)
- Add ML classifier integration via gRPC as a pattern-engine signal source (#45)
- Add mobile / on-call surface for escalation response (#44)
- Add live federation of mod conversations across labeler instances (#43)
- Define Polaris-owned NSIDs for cross-instance federation (#42)
- Add hardware-key (WebAuthn) requirement config flag with per-profile enforcement (#40)
- Add threat-model coverage test suite (T1-T6) (#39)
- Add docker-compose and Helm deployment artifacts plus backup runbook (#38)
- Add hash-chained audit log with external attestation of head hash (#35)
- Add proto-blue-lexicon validation engine and Registry to the wasm bundle (#34)
- Implement evidence-preservation CAR snapshotter on action commit (#33)
- Implement inbound third-party labeler consumer with trust weights (#32)
- Implement AtprotoOauthAuthVerifier as second ModeratorAuth backend (#31)
- Implement polaris labeler-key rotate CLI (#30)
- Implement K-256 Label record construction and signing (#28)
- Implement SigningKey trait with file-plain, passphrase-sealed, os-keychain, cloud-kms-oracle impls (#29)
- Add polaris-publish-labeler-record CLI to declare the labeler on Bluesky (#27)
- Host com.atproto.label.subscribeLabels and queryLabels via proto-blue-xrpc (#26)
- Add second-opinion conversation attachments with full-text search (#25)
- Add appeals workflow as linked incidents (#24)
- Implement exposure tracking per moderator with operator-controlled caps (#23)
- Implement category and specialty routing for incident assignment (#22)
- Add pattern action endpoints with senior co-sign gating (#21)
- Build Leptos pattern dashboard as the default home view (#20)
- Add report-volume anomaly bands using rolling statistics (#19)
- Implement MinHash account-cohort detection (sock-puppet rings) (#18)
- Implement SimHash image-hash dedup for coordinated-image detection (#17)
- Add event bus abstraction with Kafka and NATS backends (feature-gated) (#16)
- Implement action reversal workflow with 24h moderator window and indefinite senior override (#36)
- Build Leptos subject-centric case view UI (#15)
- Implement subject-centric case API on Axum (#14)
- Add Subject, Incident, Action, Report Postgres schema and sqlx repositories (#13)
- Implement firehose ingest worker using proto_blue::repo::Firehose (#12)
- Add xtask check-frontend-boundary script enforcing API boundary at CI (#11)
- Scaffold polaris-frontend Leptos app with wasm32 CI verification (#10)
- Scaffold ModeratorAuth trait with OIDC implementation and Polaris session cookies (#9)
- Add Postgres + sqlx scaffold with compile-time-checked migrations (#8)
- Set up Cargo workspace with polaris-types, polaris-backend, polaris-frontend, xtask crates (#7)
