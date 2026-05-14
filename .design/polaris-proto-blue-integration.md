# Feature: Polaris tech architecture — proto-blue integration

## Summary

This document iterates the tech-side sections of `design.md` v0.2 (§3 Architecture, §5.9 Labeler interop, §6 Backend Implementation Notes, §7 Frontend Implementation Notes) by grounding Polaris on `proto-blue` — the in-house ATProto SDK at `/home/doll/proto-blue/proto-blue` — in place of the originally-named `atrium-api`. The shape of Polaris does not change; the bindings to ATProto do. Four decisions concretize the iteration: Polaris hosts its own labeler XRPC endpoint (rather than emitting to an external one), moderator authentication is pluggable across OIDC and ATProto OAuth, the Leptos frontend reads public ATProto data directly via wasm-compiled proto-blue while all non-public state stays Axum-proxied, and Polaris's internal data model stays as plain Rust types with no Polaris-owned NSIDs in v1.

## Requirements

- REQ-1: Polaris hosts `com.atproto.label.subscribeLabels` and `com.atproto.label.queryLabels` as a native XRPC server using `proto_blue_xrpc::server::XrpcServer` (the `server` feature of `proto-blue-xrpc`, which mounts on an `axum::Router`). Polaris is the labeler service that downstream AppViews subscribe to, not a producer that writes into an external labeler.
- REQ-2: Polaris ships a small administrative binary (`polaris-publish-labeler-record`) that writes an `app.bsky.labeler.service` record to the operator's controlled Bluesky account, declaring the public hostname and the labeler's signing key. The record is constructed from the generated type `proto_blue_api::generated::app::bsky::labeler::service`.
- REQ-3: Every `Action` of kind `Label` or `Takedown` produces a `com.atproto.label.defs::Label` value (from `proto_blue_api::generated::com::atproto::label::defs`) signed with a K-256 keypair via `proto_blue_crypto`. The signed `Label` is what `subscribeLabels` streams to consumers.
- REQ-4: Moderator authentication is gated by a `polaris-backend` `ModeratorAuth` trait, shaped after `proto_blue_xrpc::server::AuthVerifier`, with two compiled-in implementations: `OidcAuthVerifier` (uses `openidconnect` against an operator IdP) and `AtprotoOauthAuthVerifier` (wraps `proto_blue_oauth::OAuthClient`). The active backend is selected at startup from a config key `[auth] backend = "oidc" | "atproto"`.
- REQ-5: The Leptos frontend in `polaris-frontend` depends on the `proto-blue` umbrella crate; building for `wasm32-unknown-unknown` automatically selects the wasm-clean backends (`fetch-web` for XRPC, `gloo-ws` for WebSocket, browser-side identity/api/oauth) via proto-blue's target-conditional Cargo dependency table — no feature gymnastics on the consumer side. Read paths for public ATProto data (profile lookups, public posts, public blobs) go through a `PublicAtprotoClient` abstraction that calls proto-blue directly from the browser.
- REQ-6: All non-public state — incidents, reports, observations, actions, moderator session, audit log — is exposed only through Polaris's first-party HTTP API on Axum. The Leptos frontend has no code path that reaches a Polaris mutating endpoint via XRPC or a non-Polaris transport.
- REQ-7: The internal data model (`Subject`, `Incident`, `Action`, `Observation` as defined in `design.md` §4) lives in a `polaris-types` workspace crate as plain `serde`-derived Rust structs. No Polaris-owned NSIDs (e.g., `gay.dollspace.polaris.incident`) are authored in v1.
- REQ-8: Firehose ingest uses `proto_blue::repo::Firehose` (the higher-level firehose abstraction the umbrella crate exposes when its `ws` feature is enabled), persisting the `seq` cursor to Postgres on each batch flush and resuming from the persisted cursor on reconnect.
- REQ-9: Inbound label signals from third-party labelers (`design.md` §5.9) are consumed via the generated `com.atproto.label.subscribeLabels` client over `proto-blue-ws`, one connection per configured upstream. Each upstream's labels are persisted as an `Observation { kind: ExternalLabel { source: Did, label_value: String, weight: f32 }, ... }` attached to the matching `Subject`.
- REQ-10: Evidence preservation: when a moderator takes action on an ATProto record, an evidence worker fetches the relevant slice of the subject's repo (typed `com.atproto.sync.getBlocks` call via `proto_blue_xrpc::XrpcClient`, MST traversal via `proto_blue_repo`), packages the slice as a CAR file (`proto_blue_repo::blocks_to_car`), and stores the CAR in object storage. The `Action` row references the CAR by content hash.
- REQ-11: Signing-key custody is abstracted by a `SigningKey` trait in `polaris-backend`. Four implementations ship in v1, selected at startup from `[labeler.signing_key] mode`: `file-plain` (plaintext, default for labeler profile, matches Ozone's `OZONE_SIGNING_KEY_HEX` posture), `passphrase-sealed` (AES-256-GCM + scrypt), `os-keychain` (OS-native wrapping), and `cloud-kms-oracle` (KMS RPC per signature, default for Bluesky profile, only mode that defends code-execution-as-service). Startup logs a clearly-worded WARN identifying the posture when `file-plain` is selected. The Bluesky profile rejects `file-plain` at startup.
- REQ-12: Key rotation is a first-class operation. `polaris labeler-key rotate` generates a new K-256 keypair via `proto-blue-crypto`, writes an updated `app.bsky.labeler.service` record declaring the new public key, retains the old public key in a `revoked_keys` table so historical labels remain verifiable against their issuance-time key, and switches active signing to the new key. Rotation works with all four `SigningKey` modes (the mode-specific work is generating + persisting the new key material in the same custody store).
- REQ-13: `polaris-frontend` includes the `proto-blue-lexicon` validation engine in its wasm bundle. The frontend constructs a minimal `proto_blue_lexicon::Registry` containing at least the schemas operators can author records against in the UI (v1 surface: `com.atproto.label.defs` and `app.bsky.labeler.service`) and validates user-constructed records against the registry before submission. Validation errors surface inline without a network round-trip.

## Acceptance Criteria

- [ ] AC-1: A downstream consumer connecting to `wss://{polaris-host}/xrpc/com.atproto.label.subscribeLabels` receives a properly-framed stream of `Label` records signed by the labeler's K-256 key; signature verification against the labeler's declared signing key (from its `app.bsky.labeler.service` record) passes for every emitted label. Verified by an integration test that uses `proto-blue-interop-tests`'s differential harness against the `@atproto/*` TypeScript SDK as the consumer.
- [ ] AC-2: Running `polaris-publish-labeler-record --account {handle} --signing-pubkey {did:key}` against a configured Bluesky operator account writes an `app.bsky.labeler.service` record to that account's repo, and the record validates against the lexicon registered in `proto_blue_lexicon`.
- [ ] AC-3: A `Label` record emitted by Polaris is consumed without error by `proto-blue`'s own `subscribeLabels` consumer in a round-trip test (`polaris-backend` emits, separate test client subscribes).
- [ ] AC-4: Two `ModeratorAuth` impls exist in `polaris-backend/src/auth/`: `oidc.rs` and `atproto.rs`. Each has an integration test that drives a synthetic moderator login end-to-end and produces an `AuthContext` carrying `moderator_id` plus a non-empty role set.
- [ ] AC-5: With `[auth] backend = "atproto"` in config, a moderator completes a full PAR + PKCE + DPoP login flow against `bsky.social` and reaches the dashboard. With `[auth] backend = "oidc"`, the same end-state is reached against a configured OIDC provider (test uses `mock-oidc`).
- [ ] AC-6: `polaris-frontend` builds for `wasm32-unknown-unknown` with `proto-blue` as a dependency (default features); proto-blue's target-conditional Cargo deps select the wasm backends (`fetch-web` / `gloo-ws`) automatically. The `PublicAtprotoClient` abstraction has a `wasm` impl backed by proto-blue's `gloo-net`-driven XRPC client and a `native` impl backed by proto-blue's `reqwest`-driven XRPC client, selected by `cfg(target_arch = "wasm32")`.
- [ ] AC-7: All mutating HTTP endpoints under `/api/*` on the Axum backend reject requests without a valid Polaris session cookie (verified by `tower::ServiceExt`-driven request tests). `polaris-frontend` has no `XrpcClient` instance that targets a Polaris-owned route — enforced by a `cargo xtask check-frontend-boundary` script that greps for forbidden patterns and is wired into CI.
- [ ] AC-8: The `polaris-types` workspace crate builds standalone (no proto-blue dependency) and is imported by both `polaris-backend` and `polaris-frontend`. No type from `proto_blue_api::generated::*` appears in `polaris-types`' public surface.
- [ ] AC-9: The firehose ingest worker survives a forced WebSocket close from a fixture upstream and resumes within 30 seconds from the last persisted cursor, with no event loss across the gap (verified by replaying a recorded firehose fixture and asserting end-state byte-equality).
- [ ] AC-10: An inbound `Label` record from a configured third-party labeler is ingested, an `Observation { kind: ExternalLabel { .. } }` is attached to the matching `Subject` in Postgres within 5 seconds of receipt, and the observation surfaces in the subject's `risk_signals` denormalized field.
- [ ] AC-11: Taking action on a post (via the `POST /api/actions` endpoint, kind = `Label`) triggers the evidence worker; within 30 seconds, a CAR blob containing the post record plus its MST proof path is stored in object storage and the `Action` row carries a `evidence_car_cid` reference. Reading the CAR back through `proto_blue_repo::read_car` reproduces the post's `LexValue` byte-for-byte.
- [ ] AC-12: A `polaris-frontend` CI job runs `cargo build --target wasm32-unknown-unknown -p polaris-frontend` on every PR and fails the build on regression. Since proto-blue has no upstream CI at the time of this design, Polaris's CI is the first wasm-build verifier on the dependency chain; failures that root-cause to proto-blue are surfaced upstream by filing an issue against `dollspace-gay/proto-blue` with a reproduction.
- [ ] AC-13: `polaris-backend` ships four `SigningKey` impls under `polaris-backend/src/labeler/signer/`: `file_plain.rs`, `passphrase_sealed.rs`, `os_keychain.rs`, `cloud_kms.rs`. Each has an integration test that signs a fixture payload and verifies the signature against the impl's `public_key()`. The `os-keychain` test is gated by a `cfg!(any(target_os = "macos", target_os = "linux", target_os = "windows"))` guard and additionally by environment availability (skipped, not failed, when the keychain backend isn't present in CI).
- [ ] AC-14: Starting `polaris-backend` with `[labeler.signing_key] mode = "file-plain"` produces a single-line warning at log level WARN in the first 100 log lines, containing the strings `signing-key` and `file-plain` and a URL or path pointing at the stronger-modes documentation. Starting with `mode = "file-plain"` in the Bluesky profile (`[profile] mode = "bluesky"`) instead refuses to start and exits with a non-zero status whose error message names the disallowed mode.
- [ ] AC-15: Running `polaris labeler-key rotate` against a configured staging deployment: (a) generates a new K-256 keypair using `proto_blue_crypto`, (b) writes a new `app.bsky.labeler.service` record declaring the new public key (validated against the lexicon), (c) inserts the previous public key into the `revoked_keys` table with a `revoked_at` timestamp, (d) switches active signing to the new key, and (e) labels emitted before rotation continue to verify against the public key listed for that label's issuance timestamp. Verified end-to-end by a rotation integration test that emits a label, rotates, emits another label, and checks both signatures verify under their respective issuance keys.
- [ ] AC-16: Opening the label-action composer in the running frontend and entering invalid input (a `val` outside the labeler's declared value set, an `exp` not parseable as RFC 3339, or a missing required field) surfaces a validation error inline within 100ms of the input event, with zero HTTP requests to the Polaris backend for that validation. Verified by a headless-browser wasm test that constructs malformed records, calls `Registry::validate()`, and asserts the expected `LexValidationError` variant. The same test asserts that the `proto-blue-lexicon` validation engine is present in the built wasm bundle (`wasm-objdump` or equivalent shows the relevant symbols).

## Architecture

### A. Crate map: replacing `atrium-api`

Every reference to `atrium-api` in `design.md` v0.2 maps to a specific `proto-blue-*` crate, summarized here. The mapping is the canonical translation for §3.2, §5.9, and §6 of the original document:

| Concern                                                | proto-blue crate(s)                                          |
|--------------------------------------------------------|--------------------------------------------------------------|
| Firehose subscription                                  | `proto-blue` (`ws` feature) → `proto_blue::repo::Firehose`   |
| Hosted labeler endpoint (subscribeLabels / queryLabels) | `proto-blue-xrpc` (`server` feature) + generated lexicons   |
| Outbound XRPC (PDS reads, sync.getBlocks, etc.)         | `proto-blue-xrpc` client (`fetch-reqwest` native, `fetch-web` wasm) |
| Label record construction                              | `proto_blue_api::generated::com::atproto::label::defs::Label` |
| Label record signing                                   | `proto-blue-crypto` (K-256 ECDSA via the `k256` crate)       |
| Labeler service record (declaration on Bluesky)         | `proto_blue_api::generated::app::bsky::labeler::service`    |
| Repo / MST / CAR (evidence preservation)               | `proto-blue-repo`                                            |
| DID + handle resolution                                | `proto-blue-identity` (DNS resolver on native, HTTPS `.well-known` on wasm) |
| ATProto OAuth (moderator auth in labeler profile)       | `proto-blue-oauth`                                          |
| Lexicon types on the wire                              | `proto_blue_api::generated::com::atproto::*`, `proto_blue_lexicon` for validation |
| Frontend (wasm) ATProto access                         | `proto-blue` umbrella with `default-features = false`        |

The `proto-blue` umbrella crate (`/home/doll/proto-blue/proto-blue/crates/proto-blue/src/lib.rs`) exposes feature flags `full` (default, all subsystems on), `net` (xrpc), `ws` (websocket + `repo::Firehose`), `resolver` (identity), `oauth`, and `api`. Backend selection per target is automatic — proto-blue's `Cargo.toml` has target-conditional dependency tables (`[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` vs. `[target.'cfg(target_arch = "wasm32")'.dependencies]`) that swap `reqwest`/`tungstenite`/`hickory-resolver` (native) for `gloo-net`/`gloo-ws`/HTTPS-`.well-known` (wasm). Consumers enable features they want; the right backend lands per target.

*Caveat*: proto-blue currently has no upstream CI, so the wasm build path is structurally sound (target-conditional Cargo deps + per-subcrate `fetch-web`/`gloo-ws` features) but is not load-bearing-tested upstream. Polaris's own CI is the first wasm-build verifier on the dependency chain (AC-12).

### B. Polaris as a first-class labeler service

This is the biggest architectural shift versus `design.md` v0.2. The original §3.2 framed Polaris as "emitting labels via atrium-api" — i.e., as a label *producer* that wrote to some other labeler service. `proto-blue-xrpc`'s `server` feature gives Polaris the ability to *be* the labeler service. The model becomes:

```
                                    ┌──────────────────────────────┐
                                    │  Polaris labeler endpoint    │
                                    │  ───────────────────────     │
   AppViews, other labelers,        │  GET  /xrpc/com.atproto      │
   Bluesky-PDS clients              │       .label.queryLabels     │
   subscribing to Polaris  ────►    │  WS   /xrpc/com.atproto      │
                                    │       .label.subscribeLabels │
                                    │                              │
                                    │  Backed by proto-blue-xrpc   │
                                    │  XrpcServer mounted on the   │
                                    │  same axum::Router as the    │
                                    │  Polaris first-party API     │
                                    └──────────────────────────────┘
                                              ▲
                                              │ signed Label records
                                              │
                                    ┌──────────────────────────────┐
                                    │  Polaris emit service        │
                                    │  - new Action → Label → sign │
                                    │  - assigns seq, persists,    │
                                    │    fan-outs to subscribers   │
                                    └──────────────────────────────┘
                                              ▲
                                              │ on Action commit
                                              │
                                    ┌──────────────────────────────┐
                                    │  Polaris case store (Postgres)│
                                    │  actions, labels materialized│
                                    │  view, seq counter           │
                                    └──────────────────────────────┘
```

The `polaris-publish-labeler-record` binary (REQ-2) is a one-shot tool the operator runs at deploy time and on key rotation. It logs into the operator's Bluesky account via `proto_blue_oauth` (or accepts a long-lived app password via env var as a fallback) and writes the `app.bsky.labeler.service` record at the agreed AT-URI. The record declares Polaris's public hostname (where consumers connect for `subscribeLabels`) and the labeler's `did:key`-encoded P-256 or K-256 signing public key, which downstream verifiers fetch to authenticate Polaris's labels.

The labeler's private signing key is the most sensitive secret Polaris holds. Storage is mediated by a `SigningKey` trait owned by `polaris-backend`:

```rust
trait SigningKey: Send + Sync {
    fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError>;
    fn public_key(&self) -> &PublicKey;
}
```

v1 ships four implementations, selected at startup from `[labeler.signing_key] mode = "..."`:

| Mode                | At-rest (T1-T3) | Code-exec (T4) | Restart UX        | Notes                                                                                              |
|---------------------|------------------|------------------|--------------------|----------------------------------------------------------------------------------------------------|
| `file-plain`        | ❌               | ❌               | zero-touch         | **Default for labeler profile.** Same posture as Ozone's `OZONE_SIGNING_KEY_HEX`. Startup logs a clearly-worded WARN identifying the posture and pointing at alternatives. |
| `passphrase-sealed` | ✅               | ❌               | passphrase prompt  | AES-256-GCM at rest, scrypt KDF on the operator passphrase. Key unsealed into process memory at start. |
| `os-keychain`       | ✅               | ❌               | zero-touch         | Wrapping key in macOS Keychain / freedesktop Secret Service / Windows DPAPI; sealed file unwrapped at start. |
| `cloud-kms-oracle`  | ✅               | ✅               | zero-touch         | **Default for Bluesky profile.** Each `sign()` is an RPC to AWS / GCP / Azure KMS; key material never enters Polaris's address space. Real T4 defense at the cost of per-signature latency and a KMS dependency. |

**Why `file-plain` is the labeler-profile default.** Ozone — the de facto incumbent — ships `OZONE_SIGNING_KEY_HEX` as a plaintext hex env var on disk and offers no alternative. That is the security posture every active labeler operates under today. Polaris matches it to preserve Ozone-equivalent onboarding velocity (single-VM, `docker compose up`, no Vault or KMS account required) while shipping strictly-stronger options for operators who want them. The startup warning is part of the contract: operators see the posture every time the service starts.

**Why `cloud-kms-oracle` is the Bluesky-profile default.** First-party deployments already run KMS infrastructure; using anything else would be a regression. The Bluesky profile explicitly disallows `file-plain` at startup.

**Threat-model honesty.** The encrypted-at-rest modes (`passphrase-sealed`, `os-keychain`) defend stolen disk / backup / file disclosure but not code execution as the Polaris user — once unsealed, the key sits in process memory exactly the way the plaintext key does. Only `cloud-kms-oracle` defends T4, by keeping the key out of Polaris's address space and rate-limiting at the KMS boundary. Operators pick this trade-off explicitly per profile.

**Key rotation is a first-class operation.** Given that only one mode survives the most common compromise scenario (T4), rotation is the realistic recovery path across all modes. `polaris labeler-key rotate` is a one-command flow: generate a new K-256 keypair via `proto-blue-crypto`, write an updated `app.bsky.labeler.service` record to the operator's Bluesky account declaring the new public key, retain the old public key in a `revoked_keys` table so historical labels remain verifiable, and switch active signing to the new key. Investment in cheap, well-tested rotation buys more real security than fancier at-rest schemes — and it is the answer Ozone-class deployments rely on implicitly anyway.

### C. Pluggable `ModeratorAuth`

`design.md` §6 mandated OIDC. proto-blue ships a full ATProto OAuth 2.0 client (`proto-blue-oauth/src/client.rs` exposes `OAuthClient`, plus `DpopAlg`, `DpopKey`, `build_dpop_proof`, `PkceChallenge`, `OAuthSession`, etc.) that makes ATProto-native authentication feasible for the labeler profile. The two-profile architecture from `design.md` §3.1 maps directly:

- `polaris-backend/src/auth/oidc.rs` — `OidcAuthVerifier`. Uses the `openidconnect` crate against the operator's IdP (Okta, Auth0, in-house Keycloak, etc.). Suitable for the Bluesky first-party profile and for any operator with existing identity infra. Returns a `ModeratorAuthCtx { moderator_id: ModeratorId, roles: Vec<Role>, ... }`.
- `polaris-backend/src/auth/atproto.rs` — `AtprotoOauthAuthVerifier`. Wraps `proto_blue_oauth::OAuthClient`. The moderator enters a Bluesky handle on the login page; Polaris does identity resolution via `proto-blue-identity`, fetches the PDS's OAuth metadata, runs PAR → authorization redirect → code exchange → DPoP-bound token retrieval. The resulting DID becomes the moderator's stable id; roles are looked up locally (Polaris owns the role assignment, not Bluesky).

Both implementations are compiled into every Polaris binary unconditionally. Selection is per-process via the config key. The internal API beyond `ModeratorAuth` is identical: every Axum handler that needs a moderator pulls `Extension<ModeratorAuthCtx>` from request extensions, set by a single auth middleware that delegates to the configured backend.

Polaris sessions, regardless of backend, are server-issued opaque cookies with TTL and refresh handled by Polaris. The upstream OAuth/OIDC tokens never leave the backend; the frontend never sees them.

### D. Frontend: hybrid public-direct / private-proxied

`design.md` §7 specified "type-shared with the backend via a single Rust crate." The shape of this changes slightly:

- **`polaris-types`** (new crate) — Polaris-internal types only. `Subject`, `Incident`, `Action`, `Observation`, `Report`, `ModeratorId`, `SubjectId`, etc. Plain `serde`-derived Rust. No proto-blue dependency. Used by both `polaris-backend` and `polaris-frontend`.
- **Stock ATProto types** — come from `proto_blue_api::generated::*`. This crate compiles to both native and (incrementally) wasm. No need for a hand-rolled shared crate to carry ATProto-shaped concerns — the generated code already does that, identically on both sides.

The frontend then has two HTTP clients:

1. **`PolarisApiClient`** — talks to `https://{polaris-host}/api/*` for everything Polaris-owned. Carries the Polaris session cookie. All mutations (create incident, take action, write comment, escalate) go here. All reads that touch non-public state (full subject history, reports, observations, audit log) go here.
2. **`PublicAtprotoClient`** — abstraction over public ATProto reads. Has two impls:
   - Native (used in SSR and tests): backed by `proto_blue_xrpc::XrpcClient` with `reqwest`.
   - Wasm: backed by `proto_blue_xrpc::XrpcClient` with `gloo-net` (the `fetch-web` feature). Selected by `cfg(target_arch = "wasm32")` — the same target conditional proto-blue's own Cargo.toml uses, so the right backend lands automatically.

Call sites use the `PublicAtprotoClient` trait; transport selection is a property of the build target, not a runtime decision.

The wasm bundle additionally embeds the `proto-blue-lexicon` validation engine plus a minimal lexicon registry containing the schemas the action composer lets operators author against (`com.atproto.label.defs`, `app.bsky.labeler.service`). The bundle-size cost is an accepted trade-off for instant inline validation feedback on label-record construction — operators see schema errors as they type, not after a server round-trip. If the registry becomes a bundle constraint at scale, `proto-blue-lexicon`'s registry shape allows loading only the schemas the UI actually uses; the v1 default loads the minimum set, not the full ATProto catalog.

The boundary enforcement (AC-7) is mechanical: an `xtask check-frontend-boundary` greps `polaris-frontend/src/**/*.rs` for any reference to a path under `polaris-backend::api::mutations::*` or to a hardcoded Polaris mutating route string, and fails CI if found.

### E. Internal data model stays plain Rust

Per the decision in Phase 1: no Polaris-owned NSIDs in v1. `polaris-types` holds the `design.md` §4 types as plain Rust. The `design.md` §10 open question on "federation of mod conversations" remains open and is the natural place to introduce Polaris-owned lexicons (e.g., a `polaris.escalation` record for cross-instance handoff) when that becomes a v2 goal.

`proto-blue-codegen` is *not* depended on by Polaris in v1 — Polaris consumes the already-generated lexicons that ship in `proto-blue-api`. The codegen crate becomes relevant only when Polaris defines its own NSIDs.

### F. Firehose ingest

`proto-blue` exposes `proto_blue::repo::Firehose` when the umbrella `ws` feature is on. The ingest worker:

1. Constructs a `Firehose` configured for the operator's chosen relay (`bsky.network` for Bluesky, an operator-provided URL for labelers running against their own infrastructure).
2. Resumes from a `seq` cursor persisted in Postgres (`firehose_cursor` table, single row).
3. Decodes each `#commit` frame into typed events using `proto_blue_repo`'s MST/CAR primitives and `proto_blue_api`'s generated lexicons.
4. Emits normalized events onto the internal event bus (Kafka for Bluesky profile, NATS for labeler profile, per `design.md` §3.1) for the pattern engine to consume.
5. Batch-flushes the cursor on Postgres commit so resume is exactly-once at the cursor granularity.

The reconnection / heartbeat policy lives inside `proto-blue-ws`'s `WebSocketKeepAlive`, which `Firehose` builds on — we get auto-reconnect with exponential backoff and read-side heartbeat for free.

### G. Inbound third-party labels

Mirrors the firehose ingest worker, one connection per configured upstream labeler. For each upstream:

1. The operator configures `[[upstream_labelers]] did = "did:plc:..." weight = 0.8 categories = ["spam"]` etc.
2. Polaris resolves the upstream's `app.bsky.labeler.service` record, extracts the public hostname and signing key.
3. A `proto-blue-ws` connection to `wss://{upstream-host}/xrpc/com.atproto.label.subscribeLabels` streams labels in.
4. Each `Label` is signature-verified against the upstream's declared key (using `proto-blue-crypto`).
5. Verified labels become `Observation { kind: ExternalLabel { source, label_value, weight }, evidence: serde_json::Value, ... }` rows attached to the matching `Subject`.
6. The `Subject`'s denormalized `risk_signals` is recomputed on observation insert.

The per-category trust weight from `design.md` §10 is captured by storing the weight on the `Observation` itself at ingest time — refining the trust model later (e.g., source × category × time-decay) only requires changing the weight-computation function, not the schema.

### H. Evidence preservation via `proto-blue-repo`

A new subsystem not in `design.md` v0.2, motivated by having `proto-blue-repo` available. When `POST /api/actions` commits an action against a record-shaped subject, an evidence worker job is enqueued. The worker:

1. Resolves the subject's repo location (`com.atproto.repo.describeRepo` via `XrpcClient`).
2. Calls `com.atproto.sync.getBlocks` for the record CID and its MST proof path (the minimum CAR slice needed to verify the record's inclusion in a signed commit).
3. Packages the slice using `proto_blue_repo::blocks_to_car` into a CAR file.
4. Hashes the CAR (SHA-256), stores the bytes in object storage at `evidence/{sha256-prefix}/{sha256-hex}`, and updates the `Action` row's `evidence_car_cid` column with the content hash.
5. The CAR is retained for the audit lifetime of the `Action` (currently: indefinitely; subject and action history is permanent per `design.md` §4).

The proof: a future appeal or audit can read the stored CAR through `proto_blue_repo::read_car` and verify that the record at action time matches what Polaris claimed it was, regardless of whether the upstream record has since been edited or deleted.

### I. Files / paths that materialize this design

These are the new crates and modules the implementation will create. Listed for traceability against requirements; they don't all exist yet (this is a greenfield repo — only `design.md`, `LICENSE`, `README.md`, and `.crosslink/` are present today, verified by `ls /home/doll/Polaris/`):

- `polaris-types/` — workspace crate. Subject/Incident/Action/Observation/Report/ModeratorId.
- `polaris-backend/` — workspace crate. Axum app, ingest workers, emit service, evidence worker.
  - `src/auth/oidc.rs` — `OidcAuthVerifier`.
  - `src/auth/atproto.rs` — `AtprotoOauthAuthVerifier`.
  - `src/labeler/server.rs` — mounts `proto_blue_xrpc::server::XrpcServer` for `subscribeLabels`/`queryLabels`.
  - `src/labeler/signer.rs` — `SigningKey` trait + KMS-backed and file-backed impls.
  - `src/ingest/firehose.rs` — `proto_blue::repo::Firehose` driver.
  - `src/ingest/upstream_labels.rs` — third-party label consumer.
  - `src/evidence/worker.rs` — CAR snapshotting on action commit.
- `polaris-frontend/` — workspace crate. Leptos app.
  - `src/atproto_client.rs` — `PublicAtprotoClient` trait + native + wasm impls.
  - `src/api_client.rs` — `PolarisApiClient`.
- `polaris-publish-labeler-record/` — binary crate. Operator tool.
- `xtask/` — boundary check (AC-7) and other workspace tooling.

The pattern engine, case store schema, wellness instrumentation, and routing layer are unaffected by this iteration and continue per `design.md` §3.2, §4, §5.4, §5.7.

## Open Questions

### Q1: wasm-readiness gating for `PublicAtprotoClient` — RESOLVED

Originally flagged based on stale "🚧 (issue #25/#26/#27)" markers in `proto-blue/crates/proto-blue/src/lib.rs`. On verification (2026-05-14): those issue numbers point to closed codegen + interop test work, not wasm tickets, and no wasm tickets exist in proto-blue's tracker because the wasm work is already shipped. proto-blue's `Cargo.toml` has target-conditional dependency tables that automatically select `fetch-web` / `gloo-ws` / browser-side backends on `wasm32-unknown-unknown`. The structural risk that remains — proto-blue has no upstream CI — is captured by AC-12, which makes Polaris's own CI the first wasm-build verifier.

A follow-up issue has been filed against proto-blue to fix the stale rustdoc table.

### Q2: Labeler signing key custody for self-hosted labeler profile — RESOLVED

The question was: what is the default at-rest custody for a self-hosted labeler's signing key?

Resolution (informed by Ozone's actual posture, see §B): Polaris ships a `SigningKey` trait with four implementations — `file-plain`, `passphrase-sealed`, `os-keychain`, `cloud-kms-oracle`. The labeler-profile default is `file-plain` (matching Ozone's `OZONE_SIGNING_KEY_HEX` posture so migration costs nothing in onboarding velocity), with a startup warning that names the posture and points at alternatives. The Bluesky-profile default is `cloud-kms-oracle` and rejects `file-plain` at startup. Key rotation is first-class (REQ-12 / AC-15); investment in cheap rotation is the dominant security improvement over Ozone, not the at-rest mode.

Threat-model honesty drove the choice: encrypted-at-rest modes (`passphrase-sealed`, `os-keychain`) defend stolen disk / backup / file disclosure but not code execution as the Polaris user. Only `cloud-kms-oracle` defends T4, at the cost of per-signature KMS latency. Operators pick the trade-off explicitly per profile.

### Q3: `polaris-frontend` wasm bundle inclusion of `proto-blue-lexicon` — RESOLVED

Resolution: include. The frontend bundles `proto-blue-lexicon` and constructs a minimal `Registry` containing the schemas operators can author records against in the UI (`com.atproto.label.defs`, `app.bsky.labeler.service` for v1). All user-constructed records are validated client-side via `Registry::validate()` before submission; errors surface inline with no network round-trip.

Instant validation feedback is the UX win that justifies the bundle-size cost. The registry's shape allows loading only the schemas the UI actually needs, so the bundle carries the minimum lexicon set rather than the full ATProto catalog. If the cost becomes a real constraint at scale, the registry is structured to allow further trimming without breaking the validation contract.

Captured by REQ-13 and AC-16.

## Out of Scope

- Defining Polaris-owned NSIDs (`polaris.incident`, `polaris.observation`, etc.). Deferred to a future iteration; folded into `design.md` §10's federation question.
- Migrating off OIDC in environments that already deploy it. The two backends coexist; no migration path is mandated either direction.
- Forking or vendoring proto-blue. Polaris depends on `proto-blue` as a normal crates.io dependency — `proto-blue = "0.3"` in `Cargo.toml`, current version `0.3.1` (verified on crates.io, repo `https://github.com/dollspace-gay/proto-blue`, license `MIT OR Apache-2.0`). Subcrates (`proto-blue-xrpc`, `proto-blue-oauth`, etc.) are also published and can be depended on directly when à-la-carte feature selection is preferable to the umbrella crate.
- Live federation of mod conversations across labeler instances (`design.md` §10). Out of scope for this tech iteration.
- Migration tooling for operators currently running Ozone. Separate design. Note: Polaris's `file-plain` signing-key mode reads the same hex-encoded K-256 secret Ozone stores as `OZONE_SIGNING_KEY_HEX`, so the signing-key half of a migration is a config rename, not a re-key.
- TPM-sealed signing keys (PCR-bound at-rest). Post-v1; depends on operator demand and on `tpm2-tss` Rust bindings stabilizing.
- Hardware-token signing keys (YubiKey / FIDO2 / PKCS#11 HSM). Post-v1; not viable for unattended labeler deployment without a separate attended-signing UX.
- Mobile / on-call surface (`design.md` §10). Out of scope.
- ML classifier integration shape (`design.md` §10). Out of scope; orthogonal to the proto-blue integration.
