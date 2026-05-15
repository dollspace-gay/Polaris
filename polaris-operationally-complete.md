---
title: "Polaris operationally complete labeler (M5 close-out)"
tags: ["design-doc"]
sources: []
contributors: ["TeIq"]
created: 2026-05-15
updated: 2026-05-15
---


## Design Specification

### Summary

Close the gap between Polaris's structurally-shipped M5 ("baseline through M3 +
M4", per `git log`) and an operationally complete ATProto labeler that a real
operator can stand up, run a moderation session against, and verify
downstream. The smoke-test session against `polarislabeler.bsky.social`
revealed seven discrete gaps (frontend has no CSS, labeler signer refuses to
boot without a pre-existing key, PLC operations sent replace-shaped payloads
that broke existing keys, OAuth scope was too narrow, bodyless POST helper
missing, DPoP-nonce retry missing on resource-server posts, bincode envelope
broke serde round-trip with optional fields). All of those were patched in
the smoke session — this design captures the remaining work to make the
producer slice operationally complete: dashboard you can actually click,
boot from a zero-state install, ops/observability surface, and CI that
re-traps the failure modes we hit.

### Requirements

- REQ-A1: A new `StubSigner` type implements [`SigningKey`](polaris-backend/src/labeler/signer/mod.rs:173) but returns `SigningError::Sign { reason: "labeler signing key not yet provisioned" }` from `sign()`. `public_key_did()` returns the empty string so callers can treat it as "no key advertised yet".
- REQ-A2: [`build_signing_key`](polaris-backend/src/labeler/signer/mod.rs:258) returns `Ok(Arc::new(StubSigner::new(path)))` when the configured `LabelerSigningKeyConfig::FilePlain { path }` points at a missing or empty file, rather than propagating `SigningError::KeyLoad`. A single startup WARN logs the deferred-provisioning posture with a pointer to the setup wizard.
- REQ-A3: [`cases::submit_action`](polaris-backend/src/api/cases.rs) checks `polaris_setup_state.signing_pubkey_did IS NOT NULL` for actions whose `kind ∈ {Label, Takedown}` before invoking the emitter; missing key surfaces as `412 Precondition Failed` with body `{"code": "labeler_not_provisioned", "error": "complete /setup before recording labelling actions"}`.
- REQ-A4: [`setup::generate_key`](polaris-backend/src/api/setup.rs:173) hot-swaps the freshly-loaded signer through `ApiState::active_signer` (the existing [`tokio::sync::watch::Sender<Arc<dyn SigningKey>>`](polaris-backend/src/api/state.rs) channel that issue #65's key-rotation work installed) after writing the key file to disk, so the next emit picks up the real signer atomically without a process restart.
- REQ-A5: With an empty `.smoke/labeler.key` (or no env var pointing at one) and an empty `polaris_setup_state` row, `polaris-backend` boots, listens on its bind port, serves `/healthz` (200), serves `/setup` (renders the wizard), and serves `/oauth/client-metadata.json` (200). ### B. Dashboard styling — make the existing surface usable
- REQ-B1: `polaris-frontend/styles/` contains hand-written CSS files keyed by component group (`reset.css`, `tokens.css`, `pattern-dashboard.css`, `case-view.css`, `action-composer.css`, `setup-wizard.css`, `login.css`). Trunk picks them up via `<link data-trunk rel="css" href="styles/*.css">` entries in [`polaris-frontend/index.html`](polaris-frontend/index.html).
- REQ-B2: Every BEM class name referenced in `polaris-frontend/src/{pages,components}/**.rs` has at least one matching rule in the styles directory. A test in `polaris-frontend/tests/styles_coverage.rs` greps the Rust source for `class=".*?"` literals and asserts each class appears in at least one `.css` file.
- REQ-B3: The submit button on the [`ActionComposer`](polaris-frontend/src/components/action_composer.rs:467) is keyboard-focusable with a visible 2px focus ring; the disabled state (reasoning < 10 chars OR lexicon invalid) is visually distinct (lowered opacity + `not-allowed` cursor); the lexicon error message is rendered in a colour that satisfies WCAG AA contrast against the panel background.
- REQ-B4: The [`pattern-dashboard__grid`](polaris-frontend/src/pages/dashboard.rs:264) collapses from 12-column to single-column at viewports ≤ 768px. The four dashboard panels stay readable on a 360px-wide phone viewport.
- REQ-B5: Design tokens (colour, spacing, typography, radius) live in `polaris-frontend/styles/tokens.css` as CSS custom properties under `:root`, with a `prefers-color-scheme: dark` block overriding the dark palette. Component CSS only references the tokens, never literal colour values. ### C. Label emit + verify — close the deferred end-to-end test
- REQ-C1: A new hermetic integration test `polaris-backend/tests/subscribe_labels_e2e.rs` boots the production router via [`router_with_state`](polaris-backend/src/api/mod.rs:77), opens a WebSocket subscription against `/xrpc/com.atproto.label.subscribeLabels`, triggers an action via `POST /api/cases/{subject_id}/actions` (which flows through `LabelEmitter::emit`), receives the broadcast label frame on the WebSocket, decodes the CBOR-framed body, and calls [`verify_label`](polaris-backend/src/labeler/verify.rs:79) against the current labeler signing key. This closes the deferral at [`tests/labels_xrpc.rs:13-18`](polaris-backend/tests/labels_xrpc.rs).
- REQ-C2: A regression test `polaris-backend/tests/setup_plc_op_shape.rs` calls [`submit_plc_operation`](polaris-backend/src/api/setup.rs:545) against a MockFetcher PDS that records the `signPlcOperation` body, then asserts: (a) `services` is an object (not array), (b) `services.atproto_pds` exists with `type` + `endpoint` keys, (c) `services.atproto_labeler` exists with the wizard-supplied service URL, (d) `verificationMethods` is an object, (e) `verificationMethods.atproto` matches the existing identity key from the resolved DID document, (f) `verificationMethods.atproto_label` matches the labeler's `did:key:z…`.
- REQ-C3: A label emitted by `LabelEmitter::emit` against the canonical Bluesky labeler signing chain is parseable by `proto_blue::api::com::atproto::label::defs::Label::deserialize` and passes `proto_blue::crypto::verify_signature` against the `did:key:z…` advertised in `polaris_setup_state.signing_pubkey_did`. Covered by a unit assertion inside the test in REQ-C1. ### D. Ops surface
- REQ-D1: A new `/readyz` endpoint reports JSON: ```json { "ready": bool, "signing_key_provisioned": bool, "last_emit_at": "RFC3339"|null, "db_reachable": bool, "setup_complete": bool } ``` Mounted on the public router (alongside `/healthz`). Used by Kubernetes readiness probes / Docker Compose health checks to gate traffic until the wizard has run.
- REQ-D2: A `/metrics` endpoint in Prometheus text exposition format, layering `axum-prometheus` on top of the `metrics-exporter-prometheus` recorder. Auto-instrumented HTTP-level histograms come from `axum-prometheus`'s middleware; the producer-slice business counters are hand-emitted via `metrics::counter!` at the action / emit / PLC sites. Exported series at minimum:; From axum-prometheus (automatic):; `axum_http_requests_total{method,path,status}`; `axum_http_requests_duration_seconds{method,path}` histogram; Hand-emitted:; `polaris_actions_total{kind}` counter (kind ∈ `label|takedown|mute|warn|escalate|no_action`); `polaris_labels_emitted_total{val,neg}` counter; `polaris_subscribe_labels_subscribers` gauge (current active WS subscriber count); `polaris_plc_operations_total{status}` counter (status ∈ `success|failed`); `polaris_setup_wizard_steps_total{step,status}` counter (step ∈ `generate_key|publish_labeler_record|request_plc_signature|submit_plc_operation`) Adds `metrics`, `metrics-exporter-prometheus`, and `axum-prometheus` to workspace deps.
- REQ-D3: Every action handler in [`polaris-backend/src/api/cases.rs`](polaris-backend/src/api/cases.rs) and the emitter at [`polaris-backend/src/labeler/emitter.rs:265`](polaris-backend/src/labeler/emitter.rs) emits a tracing span carrying `action_id` (UUID); the emitted label's `labels` row stores the same `action_id` (already present per schema), so an operator can grep logs by `action_id` and reconstruct the full action → sign → persist → broadcast → ack timeline.
- REQ-D4: A new operator runbook at `docs/ops/runbook.md` documents: bootstrap from a fresh empty database, what every step of the setup wizard does on the wire, key rotation (linking to existing `docs/ops/key-rotation.md` if present), recovering a stuck setup wizard (truncating `polaris_setup_state` to redo), required env vars, what `/healthz` vs `/readyz` mean, and the metrics names + their alerting thresholds. ### E. CI smoke + contract tests
- REQ-E1: `polaris-backend/tests/smoke_e2e.rs` walks the producer slice end-to-end under a `MockFetcher`: PDS metadata discovery → PAR → token exchange → cookie minted → `whoami` returns `first_run=true` → wizard steps 1-4 succeed → action submitted → label row lands in DB → WebSocket consumer receives + verifies. Hermetic via the [`testcontainers`](https://docs.rs/testcontainers) Postgres pattern already used in [`polaris-backend/tests/threats_common/mod.rs`](polaris-backend/tests/threats_common/mod.rs).
- REQ-E2: A new xtask target `cargo xtask lexicon-contract` fetches Bluesky's published lexicon JSONs from `github.com/bluesky-social/atproto` (paths: `lexicons/app/bsky/labeler/service.json`, `lexicons/com/atproto/label/defs.json`, `lexicons/com/atproto/identity/{requestPlcOperationSignature,signPlcOperation,submitPlcOperation}.json`, `lexicons/com/atproto/repo/putRecord.json`) at a pinned commit SHA, then re-runs [`polaris_publish_labeler_record::validate_record`](polaris-publish-labeler-record/src/lib.rs:249) + the proto-blue input-shape derivations against the fresh schemas. A drift fails the task with a diff-style message naming which field changed.
- REQ-E3: A `.github/workflows/lexicon-contract.yml` job runs `cargo xtask lexicon-contract` on a weekly cron and on manual dispatch. Each failed run opens a **new GitHub issue** (via `peter-evans/create-issue-from-file` or equivalent) labelled `lexicon-drift` carrying the diff body. The PR-blocking CI does NOT depend on this job — drift is monitored, not gating. The "new issue per failure" policy is chosen over a single rolling issue so per-event visibility is preserved at the cost of occasional duplicates while a drift is being resolved; closing the issue is the operator signal that the drift was addressed.
- REQ-E4: The existing `.github/workflows/ci.yml` `test` job includes `tests/smoke_e2e.rs` in its `cargo test --workspace` invocation. The job fails any PR that breaks the smoke.
- REQ-E5: A `make smoke-local` target (or `cargo xtask smoke-local`) spins up a Docker Compose stack with Postgres + a MockFetcher-shaped HTTP server (the same fixture the test uses, but standalone) and runs the same smoke flow an operator would step through manually, for pre-merge confidence.

### Acceptance Criteria

- [ ] AC-A1: `StubSigner` exists; `cargo test -p polaris-backend stub_signer_returns_structured_error` passes (sign() rejects, did is empty).
- [ ] AC-A2: `cargo test -p polaris-backend build_signing_key_stubs_missing_file_plain` passes — `build_signing_key` returns Ok for a non-existent path.
- [ ] AC-A3: A new test `tests/action_blocked_before_provisioning.rs` POSTs a Label action with `polaris_setup_state.signing_pubkey_did = NULL`; assertion: response is `412 Precondition Failed` with code `labeler_not_provisioned`. No `labels` row is written.
- [ ] AC-A4: `tests/setup_endpoints.rs::generate_key_hot_swaps_signer` POSTs `/api/setup/generate-key`, then issues a Label action without restarting the process; the emitter signs the label with the new key.
- [ ] AC-A5: `tests/boot_from_zero.rs` boots `polaris-backend` against a fresh empty database with no key file; asserts `/healthz` returns 200, `/setup` returns 200, and `/oauth/client-metadata.json` returns 200.
- [ ] AC-B1: `ls polaris-frontend/styles/*.css` lists at least seven files; `index.html` contains a `<link data-trunk rel="css">` entry per file. `trunk build --release` succeeds.
- [ ] AC-B2: `tests/styles_coverage.rs` walks the Rust source, extracts every class literal, and asserts each appears in at least one CSS file.
- [ ] AC-B3: A wasm-bindgen-test driven by `wasm-bindgen-test --headless --firefox` mounts `ActionComposer`, focuses the submit button, screenshots the focus ring rectangle, and asserts the focused-state border colour is ≥ 3:1 contrast against the panel.
- [ ] AC-B4: A snapshot test renders `PatternDashboard` at 360px / 768px / 1280px widths and asserts the grid template-columns differ between breakpoints.
- [ ] AC-B5: `polaris-frontend/styles/tokens.css` exposes `--color-bg-primary`, `--color-fg-primary`, `--color-accent`, `--space-sm`, `--space-md`, `--space-lg`, `--radius-sm`, `--radius-md`, `--font-mono`, `--font-sans`; tests grep the other CSS files for literal hex colours and fail the build on any match outside `tokens.css`.
- [ ] AC-C1: `cargo test -p polaris-backend --test subscribe_labels_e2e` passes. Decoded label's `sig` field verifies against the labeler's `signing_pubkey_did` from `polaris_setup_state`.
- [ ] AC-C2: `cargo test -p polaris-backend --test setup_plc_op_shape` passes; mock-recorded PLC body's `services` and `verificationMethods` match the shape defined in REQ-C2.
- [ ] AC-C3: Subsumed by AC-C1.
- [ ] AC-D1: `curl http://127.0.0.1:8080/readyz` returns a JSON body with the five named fields when the server is up; an integration test asserts the boolean values transition correctly across boot → setup-wizard completion → first-emit.
- [ ] AC-D2: `curl http://127.0.0.1:8080/metrics | grep polaris_actions_total` returns a non-empty line after at least one action has been submitted.
- [ ] AC-D3: A `tracing_test` capture verifies that submitting an action produces log spans containing the same `action_id` at the cases::submit_action, emitter::emit, and broadcaster::publish sites.
- [ ] AC-D4: `docs/ops/runbook.md` exists and is at least 200 lines; a CI markdown-lint job verifies headings + internal links.
- [ ] AC-E1: `cargo test -p polaris-backend --test smoke_e2e` passes in CI on every PR; the test runs in under 60 seconds wall-clock.
- [ ] AC-E2: `cargo xtask lexicon-contract` runs locally and exits 0 against the currently-pinned upstream commit.
- [ ] AC-E3: `.github/workflows/lexicon-contract.yml` exists and is scheduled (`schedule: { cron: '0 6 * * 1' }`); on failure it opens or comments on a GitHub issue using the existing GitHub Actions issue-bot pattern.
- [ ] AC-E4: The main CI workflow's `test` job lists `smoke_e2e` in its output; a deliberately-broken commit fails it.
- [ ] AC-E5: `make smoke-local` (or equivalent) succeeds on a clean clone with only Docker installed.

### Architecture

This work spans five workstreams (A–E above) on a workspace that already has
the heavy machinery in place. Most requirements are wiring or surface work,
not new subsystem design.

### A. First-run boot

The rotation watch-channel pattern is the substrate. Today
[`polaris-backend/src/main.rs:88`](polaris-backend/src/main.rs:88) calls
`build_signing_key(&cfg.labeler.signing_key, cfg.profile)?` and propagates
the `SigningError::KeyLoad` failure straight to a non-zero exit if the file
is missing. Issue #65's rotation work introduced
`ApiState::active_signer: watch::Receiver<Arc<dyn SigningKey>>` plus
a held `watch::Sender<Arc<dyn SigningKey>>` (see
[`main.rs:111-115`](polaris-backend/src/main.rs)). The emitter at
[`polaris-backend/src/labeler/emitter.rs:265`](polaris-backend/src/labeler/emitter.rs)
already reads through the watch channel on every emit, so swapping the
signer mid-process is a single `signer_tx.send(new_arc)` call.

New file `polaris-backend/src/labeler/signer/stub.rs` defines `StubSigner`
implementing `SigningKey`. `build_signing_key`'s `FilePlain` arm becomes:

```rust
LabelerSigningKeyConfig::FilePlain { path } => {
    match file_plain::FilePlainSigner::from_path(path) {
        Ok(signer) => Ok(Arc::new(signer)),
        Err(SigningError::KeyLoad { .. }) if !path.exists() || is_empty(path) => {
            warn_once_deferred_provisioning(path);
            Ok(Arc::new(stub::StubSigner::new(path.clone())))
        }
        Err(e) => Err(e),
    }
}
```

`setup::generate_key` (after the existing write + DB update) loads a real
`FilePlainSigner` from the path it just wrote and pushes it through the
`active_signer` sender. The sender handle needs to be threaded onto
`ApiState` — today it is held only in `main.rs` (as `_signer_tx`). Promote
it to an `ApiState` field (`Option<Arc<watch::Sender<Arc<dyn SigningKey>>>>`)
or pass via a dedicated builder method on `ApiState`.

`cases::submit_action` gains a precondition check: before the
`emit_best_effort` call at
[`polaris-backend/src/api/cases.rs:237`](polaris-backend/src/api/cases.rs),
read `polaris_setup_state.signing_pubkey_did`; if null and `kind ∈
{Label, Takedown}`, return 412.

### B. Dashboard styling

Trunk picks up CSS files via `<link data-trunk rel="css" href="…">` in
[`polaris-frontend/index.html`](polaris-frontend/index.html). The current
index has only the Rust binding. Add link entries for each new CSS file.

The CSS organisation mirrors the BEM class names already in the source:

```
polaris-frontend/styles/
├── reset.css                  # normalize + box-sizing
├── tokens.css                 # CSS custom properties on :root
├── login.css                  # .login-page, .login-page__form
├── setup-wizard.css           # .setup-wizard, .setup-wizard__step
├── pattern-dashboard.css      # .pattern-dashboard, .pattern-dashboard__grid
├── case-view.css              # .case-view, .case-view__main
├── action-composer.css        # .action-composer + sub-elements
└── components/
    ├── cluster-list.css
    ├── report-list.css
    ├── subject-header.css
    ├── history-timeline.css
    ├── report-volume-chart.css
    ├── coordinated-signals.css
    └── moderator-load.css
```

`tokens.css` defines the design system. Bluesky's published colour palette
(open-source, Apache-2.0) is a reasonable anchor for the light/dark tokens;
the exact palette is a downstream visual-design call.

The coverage test in `polaris-frontend/tests/styles_coverage.rs` is a plain
file-walking test that runs on the native target (the Rust source is
parsed, not the wasm bundle). It uses `walkdir` + a regex like
`class\s*=\s*"([^"]+)"` to extract literals, then asserts each class
appears as a selector somewhere in `styles/**.css`.

### C. Label emit + verify e2e

The deferral at
[`tests/labels_xrpc.rs:13-18`](polaris-backend/tests/labels_xrpc.rs) cites
CBOR framing complexity. Today the labeler XRPC server lives at
[`polaris-backend/src/labeler/server.rs`](polaris-backend/src/labeler/server.rs)
and uses `proto_blue_xrpc`'s WebSocket framing. The test path is:

1. Start the production router on a dynamic port via `axum::serve`.
2. Open a `tokio-tungstenite` WebSocket to
   `ws://127.0.0.1:{port}/xrpc/com.atproto.label.subscribeLabels?cursor=0`.
3. POST `/api/cases/{subject_id}/actions` with a Label-kind body.
4. Receive a binary WS frame on the subscriber socket.
5. Decode using `proto_blue::xrpc::FrameHeader::decode` (the framing
   primitive already exists in proto-blue 0.3.2).
6. Extract `label_cbor` + `sig` from the message body.
7. Call `verify_label(&pool, &label, ...)` from
   [`polaris-backend/src/labeler/verify.rs:79`](polaris-backend/src/labeler/verify.rs).
8. Assert `Ok(())`.

The PLC shape regression at REQ-C2 reuses the MockFetcher pattern from
[`tests/setup_endpoints.rs`](polaris-backend/tests/setup_endpoints.rs) and
records the request body on the `signPlcOperation` route, then asserts the
exact shape.

### D. Ops surface

`/readyz` is a new handler in
[`polaris-backend/src/api/healthz.rs`](polaris-backend/src/api/healthz.rs)
(rename the file to `health.rs` if `healthz` is too narrow). It queries
`polaris_setup_state` for `did_document_updated_at`/`signing_pubkey_did`,
reads the active signer through `ApiState::active_signer.borrow()` to see
if it's a `StubSigner`, runs a single `SELECT 1` against the pool, and
reports `last_emit_at` via a new `MAX(signed_at) FROM labels` query.

`/metrics` is a new handler. The workspace already pulls in `metrics`
transitively (via tower-http) but does not export Prometheus today. Add
`metrics-exporter-prometheus = "0.13"` to workspace deps; install a
recorder once at boot in `main.rs`; emit counters via the existing
`metrics::counter!` macros from handler sites. The `/metrics` handler
returns the recorder's text-format output.

Tracing spans for D3 use the existing `tracing` ecosystem already wired
in. The pattern is `let span = tracing::info_span!("emit_label",
action_id = %action.id);` and `.in_scope` / `.instrument` at the call
sites — well-trodden, just not yet applied at every action site.

The runbook (`docs/ops/runbook.md`) is prose work that captures what the
smoke session learned: ngrok tunnel for OAuth callback URL, env-var
matrix, Postgres bootstrap, wizard step ordering and idempotency,
labeler-key-rotate CLI, troubleshooting (sessions table truncation
recovers from stale envelope formats, etc.).

### E. CI smoke + contract tests

`tests/smoke_e2e.rs` is structurally a longer version of
`tests/setup_endpoints.rs` — same MockFetcher injection, same testcontainer
postgres, but driving a longer happy-path sequence. The MockFetcher
hosts canned responses for every HTTP request the producer slice makes:

- `https://bsky.social/.well-known/oauth-authorization-server` (AS metadata)
- `https://bsky.social/.well-known/oauth-protected-resource` (RS metadata)
- `https://bsky.social/xrpc/com.atproto.identity.resolveHandle`
- `https://plc.directory/did:plc:test123`
- `https://bsky.social/oauth/par`
- `https://bsky.social/oauth/token`
- `https://jellybaby.us-east.host.bsky.network/xrpc/com.atproto.repo.putRecord`
- `https://jellybaby.us-east.host.bsky.network/xrpc/com.atproto.identity.requestPlcOperationSignature`
- `https://jellybaby.us-east.host.bsky.network/xrpc/com.atproto.identity.signPlcOperation`
- `https://jellybaby.us-east.host.bsky.network/xrpc/com.atproto.identity.submitPlcOperation`

For each request, the mock returns the exact shape the real server sends
(captured from session logs); for the PLC and putRecord paths the mock
asserts the request body shape matches what REQ-C2 documents.

The lexicon contract task is a small Rust binary under
[`xtask/`](xtask/) (the workspace already has the xtask pattern). It
fetches lexicon JSONs from a pinned commit, deserialises them via
`proto_blue_lexicon::LexiconDoc::deserialize`, then walks the
Polaris-side wire types and asserts the field sets match.
`workflow/lexicon-contract.yml` runs the xtask on a weekly cron + on
manual dispatch.

### Out of Scope

- The consumer slice (Polaris receiving + indexing labels from third-party labelers via `subscribeLabels`). Issue #32 / REQ-9 of the integration design doc tracks this; it is its own design.
- ML-classifier integration. Tracked by `.design/m5/45-ml-classifier.md`.
- Mobile app surface. Tracked by `.design/m5/44-mobile-app.md`.
- Federated labeler discovery / inter-labeler trust signals. Tracked by `.design/m5/43-federation.md`.
- Migration tooling from Bluesky's Ozone moderation tool to Polaris. Tracked by `.design/m5/46-ozone-migration.md`.
- Real-bsky.social end-to-end CI runs. The lexicon-contract job (REQ-E2/E3) is the gauge for upstream drift; behavioural drift against a live bsky.social account would require a held service-account credential and is out of scope for this design.
- Rotation-key management (the `rotationKeys` field of the PLC operation) beyond preserving whatever the PDS currently holds. Issue #65's key-rotation work covers labeler-side key rotation; PDS-side rotation keys are owned by Bluesky.
- The `cosign` / `pattern-actions` flow's UI affordances. The backend routes exist; surfacing them in the dashboard is part of a separate design for the multi-moderator workflow.

