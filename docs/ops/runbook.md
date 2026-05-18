# Polaris Operator Runbook

Authoritative reference for operating a Polaris labeler in production.
Every claim in this document is verifiable against the source tree at
the same commit; the file references throughout this runbook are the
ground truth.

This runbook complements two narrower documents:

- [`docs/ops/quick-start.md`](./quick-start.md) — five-minute "get it
  running on my laptop" walkthrough.
- [`docs/ops/backup.md`](./backup.md) — backup and restore procedures
  for the Postgres state.

This document is the longer-form operator reference: bootstrap, the
setup wizard's wire-level behaviour, key rotation, recovery from a
stuck wizard, the env-var matrix, the health-probe contract, and the
metrics surface.

---

## 1. Bootstrap from a fresh empty database

The "zero state" assumption: a fresh Postgres database (no migrations
applied, no rows), no labeler signing-key file on disk, and a
moderator who has never run the setup wizard. Polaris is designed to
boot under these conditions and serve the wizard surface so the
operator can complete provisioning over HTTP — there is no
chicken-and-egg between "the binary boots" and "the operator runs the
wizard."

### Required environment variables before first boot

Set these in the operator's shell or systemd unit file:

```bash
export DATABASE_URL="postgres://polaris:polaris@127.0.0.1:5432/polaris"
export POLARIS_COOKIE_KEY="$(openssl rand -hex 32)"
export POLARIS_HTTP_BIND="0.0.0.0:8080"
export POLARIS_AUTH_BACKEND="atproto"
export POLARIS_ATPROTO_CLIENT_METADATA="/etc/polaris/oauth/client-metadata.json"
export POLARIS_LABELER_SIGNING_KEY_MODE="file-plain"
export POLARIS_LABELER_SIGNING_KEY_PATH="/var/lib/polaris/labeler.key"
export POLARIS_PROFILE="labeler"
export POLARIS_FRONTEND_DIST="/usr/share/polaris/dist"
```

The full env-var matrix is in section 6.

### First-start sequence

`cargo run -p polaris-backend` (or the systemd-managed binary) does
the following, in order, on first start:

1. **Configuration load.** `AppConfig::from_env` in
   [`polaris-backend/src/config.rs`](../../polaris-backend/src/config.rs)
   reads every `POLARIS_*` variable, validates each, and fails the
   process with a precise message if any required field is missing or
   malformed. The `POLARIS_COOKIE_KEY` validation rejects a zero key
   in production builds — there is no silent fall-back to an
   ephemeral key.

2. **Prometheus recorder install.** Before the router is built,
   `axum_prometheus::PrometheusMetricLayer::pair()` in
   [`polaris-backend/src/main.rs`](../../polaris-backend/src/main.rs)
   sets the global metrics recorder. From this point on, every
   `metrics::counter!` / `metrics::gauge!` call in the codebase routes
   to the same recorder, and the `/metrics` endpoint renders the
   handle's text-format output.

3. **Database connect + migrate.** `db::connect(&cfg.db)` opens the
   pool and runs every migration in `polaris-backend/migrations/`.
   The migration is idempotent: an already-migrated database is a
   no-op. The connection-pool size is hard-coded to a conservative
   default; the `POLARIS_DB_*` env override is a future addition.

4. **Build the labeler signing key.** `build_signing_key` in
   [`polaris-backend/src/labeler/signer/mod.rs`](../../polaris-backend/src/labeler/signer/mod.rs)
   inspects the configured custody mode. For `file-plain` with a
   missing or empty key file, the factory returns a `StubSigner`
   that advertises an empty DID and refuses to sign. A single startup
   WARN is logged pointing the operator at `/setup`. This is the
   "deferred provisioning" posture documented in REQ-A2 — the labeler
   boots and the wizard is reachable.

5. **Bootstrap the rotation history.** `bootstrap_active_key` in
   [`polaris-backend/src/labeler/rotation.rs`](../../polaris-backend/src/labeler/rotation.rs)
   inserts (or no-ops on conflict) the active signing key into the
   `signing_key_history` table so the historical-label verifier can
   look up issuance-time keys. With a `StubSigner` the inserted DID
   is the empty string; the row is rewritten by the wizard's
   generate-key step.

6. **Active-signer watch channel.** `main.rs` constructs a
   `tokio::sync::watch::channel(initial_signer)`. The receiver is
   installed on `ApiState::active_signer`; the sender is installed
   on `ApiState::active_signer_tx`. The wizard's
   `/api/setup/generate-key` handler pushes a freshly-loaded
   `FilePlainSigner` through the sender; the emitter reads through
   the receiver on every `emit()`. This is the hot-swap seam — no
   process restart after the wizard runs.

7. **Workers spawn.** Four detached tokio task groups start:
   - **Labeler-discovery worker** + **consumer supervisor** — see
     section [1a. Labeler discovery cold-start](#1a-labeler-discovery-cold-start)
     below for the time budget. The discovery worker walks the PLC
     directory to populate `upstream_labelers`; the supervisor spawns
     one `UpstreamLabelerConsumer::run` task per enabled row.
   - Evidence-preservation worker.
   - Report-aggregation worker.

### 1a. Labeler discovery cold-start

The case-view's "Third-party labels" panel reads from the local
`indexed_labels` table, which is populated by per-labeler firehose
subscribers (`crate::ingest::upstream_labels`). Each subscriber is
spawned by the consumer supervisor for one row in `upstream_labelers
WHERE enabled = TRUE`. The discovery worker
(`crate::ingest::labeler_discovery`) is what *fills*
`upstream_labelers` — by walking
`https://plc.directory/export` chronologically and inserting every
DID whose `operation.services.atproto_labeler` is set.

**This walk takes several hours on a fresh deploy.**

The PLC directory's `/export` endpoint returns DID-operation records
in chronological order from November 2022 forward. The total log is
~10M+ operations as of mid-2026; the worker fetches 1000 records per
page with a 250ms inter-page backoff (polite client — PLC is a
community resource). The first labeler-service record appears in
early 2024, so the first ~3M ops yield zero discovery hits before
the worker reaches the band where labeler ops start. Realistic
budget:

| Phase                                              | Wall-clock |
|----------------------------------------------------|-----------|
| Walk 2022-11 → 2024-01 (pre-labeler era)           | ~30 min   |
| Walk 2024-01 → 2025-01 (early labeler ecosystem)   | ~45 min   |
| Walk 2025-01 → present (active labeler ecosystem)  | ~60 min   |
| **Bootstrap total**                                | **~2-3 hours** |

After the bootstrap completes, the worker sleeps for 6 hours then
re-walks the delta from its persisted `last_after` cursor — these
delta passes are seconds, not hours.

**What this means for the operator:**

- On first deploy, the case-view's "Third-party labels" panel will
  render `No third-party labels are currently applied to this account`
  for every subject — *not because there are no labels*, but
  because no labeler subscribers are running yet.
- As discovery finds labelers, the supervisor spawns subscribers; as
  subscribers stream their firehose, `indexed_labels` fills with
  labels; the panel populates organically.
- The cursor is persistent: a restart resumes from where the
  previous pass stopped, not from the beginning. A daily restart
  during the bootstrap window is safe.

**Monitoring bootstrap progress:**

```sql
-- Check discovery progress
SELECT last_after, last_run_at, total_labelers_discovered
FROM plc_export_cursor;

-- Count labelers discovered so far
SELECT COUNT(*) FROM upstream_labelers WHERE enabled = TRUE;

-- Count labels persisted so far
SELECT COUNT(*) FROM indexed_labels;
```

Grep `polaris-backend` logs for `discovered new labeler` to see
labelers as they appear. Each insert fires the supervisor's
`Notify`, so a consumer task is spawned within milliseconds of
the row landing.

**Why this trade-off:** the alternative (a hardcoded labeler list
in source) silently rots when labelers come and go, and silently
hides labels from labelers the source author hasn't heard of. The
PLC walk is comprehensive: every labeler the AT-Proto network has
ever registered is discovered. The cost is paid once per deploy.

If a faster cold-start matters more than comprehensiveness, an
operator can pre-seed `upstream_labelers` via direct SQL before
starting Polaris. The supervisor honours operator-added rows the
same as discovery-added rows. Discovery still runs and will
idempotently re-insert (or update hostname for) the same DIDs.


8. **HTTP listener bind.** `tokio::net::TcpListener::bind` against
   the configured `POLARIS_HTTP_BIND`. After this point the binary
   serves traffic.

### What works while the wizard is unprovisioned

- `GET /healthz` — returns 200 (process alive + DB reachable).
- `GET /readyz` — returns **503** with
  `signing_key_provisioned: false` and `ready: false`. The
  orchestrator (Kubernetes / Compose) keeps the pod out of the
  load-balancer rotation. **But the route is still reachable** — the
  503 carries the JSON body, which the operator's tooling can scrape.
- `GET /setup` — falls through to the SPA bundle so the wizard UI
  loads.
- `GET /oauth/client-metadata.json` — returns 200 when
  `POLARIS_ATPROTO_CLIENT_METADATA` points at a real file. Required
  for atproto OAuth callbacks.
- `POST /api/cases/{subject_id}/actions` with
  `kind ∈ {label, takedown}` — returns **412 Precondition Failed**
  with code `labeler_not_provisioned`. This is REQ-A3: the gate
  refuses to record a labeling action that the labeler cannot sign.

The operator's next step is the setup wizard. Section 2 documents
exactly what each wizard step does on the wire.

---

## 2. Setup wizard — what every step does on the wire

The setup wizard's four steps are admin-gated HTTP endpoints under
`/api/setup/*`. Each handler is implemented in
[`polaris-backend/src/api/setup.rs`](../../polaris-backend/src/api/setup.rs).
The wizard's natural order is the same as the route order:

1. `POST /api/setup/generate-key`
2. `POST /api/setup/publish-labeler-record`
3. `POST /api/setup/request-plc-signature`
4. `POST /api/setup/submit-plc-operation`

The wizard UI in `polaris-frontend` walks the moderator through each
in sequence. Every step is **idempotent**: a re-POST against an
already-completed step returns the same result without side effects.

### Step 1 — generate-key

The handler:

1. Inspects `state.labeler_signing_key_cfg`. Only `file-plain` is
   reachable from this HTTP path; the other custody modes route
   through the `labeler-key-rotate` CLI (section 3) so the
   passphrase / keychain prompt / KMS RPC happens with the operator
   at a terminal, not over HTTP.
2. Probes the configured key path. Three outcomes:
   - File missing or zero bytes → mint a fresh K-256 keypair, write
     the private hex to disk with mode `0o600`, fsync. Response:
     `{ "did_key": "...", "already_provisioned": false }`.
   - File holds a valid 32-byte hex K-256 secret → derive the
     `did:key:z…`, persist it to `polaris_setup_state`, do **not**
     rewrite the file. Response:
     `{ "did_key": "...", "already_provisioned": true }`. This is
     the "operator pre-provisioned the key out of band" path; the
     wizard adopts it.
   - File holds non-empty but malformed content → **409 Conflict**
     with `refusing to overwrite`. The operator must remove the
     bad file before re-POSTing.
3. `UPDATE polaris_setup_state SET signing_key_path = $1,
   signing_pubkey_did = $2, updated_at = now() WHERE id = TRUE`.
4. Hot-swaps the labeler's active signer through the watch channel
   (REQ-A4): the next call to `LabelEmitter::emit` signs with the
   freshly-loaded `FilePlainSigner`, not the stub it was
   constructed against. This is the closure of Workstream A's
   hot-swap design.

After this step:

- `GET /readyz` flips to `ready: true` (signing key is provisioned
  and DB is reachable).
- `submit_action` with kind=Label/Takedown stops returning 412.
- The labeler-record publish (step 2) has the `did_key` it needs.

### Step 2 — publish-labeler-record

The handler:

1. Loads `polaris_setup_state.signing_pubkey_did` (set by step 1).
2. Builds the `app.bsky.labeler.service` record via
   `polaris_publish_labeler_record::build_labeler_service_record`
   using the wizard-supplied `service_url` and `label_values`. The
   shared library code is reused by the CLI so the wizard and the
   CLI emit identical wire shapes.
3. Validates the record against the lexicon
   (`polaris_publish_labeler_record::validate_record`).
4. Rebuilds the moderator's OAuth session via
   `AtprotoOauthAuthVerifier::build_oauth_session_for_moderator`.
   The session is reconstructed per-call from the sealed bundle in
   the `sessions` row so concurrent #66 refreshes are seen.
5. POSTs `com.atproto.repo.putRecord` to the moderator's PDS with
   the labeler record. The request is DPoP-bound; a single
   `use_dpop_nonce` retry is built in.
6. On success, `UPDATE polaris_setup_state SET labeler_record_uri =
   $1, updated_at = now()`. Response carries `at_uri` and `cid`.

After this step the `app.bsky.labeler.service` record exists on the
moderator's PDS. Downstream AppViews can discover the labeler by
fetching that record but signature verification is not yet possible
because the DID document does not yet point at the labeler's
verification method.

### Step 3 — request-plc-signature

The handler:

1. Rebuilds the moderator's OAuth session (same pattern as step 2).
2. POSTs **bodyless** to `com.atproto.identity.requestPlcOperationSignature`
   on the moderator's PDS. The lexicon declares no input; bsky.social's
   PDS strictly rejects any request body. The handler uses a
   bespoke bodyless DPoP-bound helper (`post_no_body_with_dpop_nonce_retry`)
   to satisfy this constraint.
3. On success, returns a human-readable message instructing the
   operator to check their email. The actual PLC token is delivered
   by the PDS's email pipeline; Polaris never sees the email
   contents.

After this step the operator must wait for the email, copy the token
out, and paste it into the wizard's step-4 form.

### Step 4 — submit-plc-operation

The handler:

1. Loads `polaris_setup_state.signing_pubkey_did`.
2. Rebuilds the moderator's OAuth session.
3. Resolves the moderator's current DID document via
   `AtprotoOauthAuthVerifier::resolve_did_document`. The resolved
   document carries the existing `services` (e.g. `atproto_pds`)
   and `verificationMethods` (e.g. `atproto`).
4. Builds a **merged** `services` map: existing entries +
   `atproto_labeler` pointing at the wizard-supplied `service_url`.
5. Builds a **merged** `verificationMethods` map: existing entries +
   `atproto_label` pointing at the labeler's `did:key:z…`. This is
   the critical merge — sending only the new key would clobber the
   PDS-controlled `atproto` identity key and break the moderator's
   normal login flow.
6. POSTs `com.atproto.identity.signPlcOperation` with `token` +
   merged `services` + merged `verificationMethods`. The PDS signs
   the operation.
7. POSTs `com.atproto.identity.submitPlcOperation` to forward the
   signed op to the PLC directory.
8. On success, `UPDATE polaris_setup_state SET
   did_document_updated_at = now()`.

After this step:

- The moderator's DID document carries the `atproto_label`
  verification method.
- `GET /readyz` reports `setup_complete: true`.
- Downstream AppViews can fetch the DID document, extract the
  `did:key:z…` for `atproto_label`, and verify signatures on labels
  Polaris emits.

The full producer slice is operational at this point.

---

## 3. Key rotation procedure

Polaris exposes two rotation surfaces:

### 3a. CLI-driven rotation — `labeler-key-rotate`

The canonical operator surface for rotating the labeler's signing
key. Implemented in
[`polaris-backend/src/bin/labeler_key_rotate.rs`](../../polaris-backend/src/bin/labeler_key_rotate.rs)
on top of the resumable state machine in
[`polaris-backend/src/labeler/rotation.rs`](../../polaris-backend/src/labeler/rotation.rs).
Invocation:

```bash
labeler-key-rotate \
  --mode file-plain \
  --new-key-path /var/lib/polaris/labeler.key.new \
  --reason "scheduled rotation 2026-Q2"
```

The state machine runs through:

1. Generate the new K-256 keypair, write to `--new-key-path` with
   mode `0o600`.
2. Insert a `signing_key_history` row with the new DID,
   `active_from = now()` and the prior key's `active_until = now()`.
   Cross-key signatures remain verifiable: the historical-label
   verifier looks up the issuance-time key by `signed_at`.
3. Publish a refreshed `app.bsky.labeler.service` record with the
   new key.
4. Drive a PLC operation that updates the `atproto_label`
   verification method.

The state is persisted between steps so a failed run resumes from
the failed step on the next invocation (`--resume`). The
`--dry-run` flag walks the plan without making any DB / wire
mutations — use it to preview before committing.

### 3b. Live-process hot-swap

The wizard's `/api/setup/generate-key` handler hot-swaps the in-
process signer through the active-signer watch channel. This is the
"single-process replace" path used during initial provisioning. The
full multi-key history tracking is **not** built into the wizard;
the wizard is for the initial provisioning, not rotation. Use the
CLI for rotation.

---

## 4. Recovering a stuck setup wizard

Symptoms:

- The wizard's UI is on step 3 but step 1 (generate-key) is being
  re-run because the operator clicked Back.
- The PDS rejected the PLC operation with `invalidToken` and the
  email token is consumed.
- `signing_pubkey_did` is populated in `polaris_setup_state` but
  the operator wants to redo from a clean state.

The recovery is to truncate the wizard's per-process state and let
the wizard run from zero. **Critically, this does NOT undo any
PDS-side artifacts** — the labeler service record on the moderator's
PDS and the PLC operation submitted in step 4 persist independently
of Polaris's local state.

### Recovery SQL

```sql
TRUNCATE TABLE sessions, auth_atproto_login_states, polaris_setup_state;
INSERT INTO polaris_setup_state (id) VALUES (TRUE);
```

Order matters:

- `sessions` carries the moderator's bound OAuth refresh-token
  envelope. Truncating it forces the moderator to re-login through
  the atproto OAuth flow, which reissues a fresh session bound to a
  fresh DPoP key.
- `auth_atproto_login_states` carries the in-flight PKCE / PAR
  state. Truncating clears any half-completed login.
- `polaris_setup_state` is the wizard's per-process state.
  Truncating + reinserting the sentinel row (`id = TRUE`) gives the
  wizard a clean canvas.

### What survives the recovery

- The labeler signing key file at
  `POLARIS_LABELER_SIGNING_KEY_PATH`. If the operator wants a fresh
  key, delete the file before re-running step 1 — the wizard will
  mint a new keypair against the same path.
- The moderator's PDS `app.bsky.labeler.service` record (step 2's
  artifact). A re-POST against the same record key (`self`) updates
  the existing record in place; the moderator does not need to
  delete the old record first.
- The PLC operation submitted in step 4. PLC operations are
  immutable once submitted; they form a chain on the DID. A
  subsequent wizard run that re-submits the same operation will fail
  the PLC directory's deduplication check unless the inputs (the
  labeler's `did:key`) have changed.

In practice: if the operator's intent is "redo the wizard with the
same labeler key," steps 2 + 4 are no-ops (idempotent). If the
intent is "redo with a fresh key," they should also delete the key
file before re-running, and the resulting PLC operation will be a
new one because the merged `verificationMethods` will carry a
different `atproto_label` did:key.

---

## 5. Health probe contract — `/healthz` vs `/readyz`

Polaris exposes two probes on the public subtree (no auth):

### `/healthz` — liveness

Implemented in
[`polaris-backend/src/api/healthz.rs`](../../polaris-backend/src/api/healthz.rs).
Returns:

- `200 OK` with `{"status":"ok","db":"ok"}` when `Db::ping` succeeds
  (the pool can hand out a connection).
- `503 Service Unavailable` with `{"status":"degraded","db":"..."}`
  when the ping fails.

The handler runs **no SQL** — it only verifies pool health. This
keeps the liveness probe cheap (no row read) and means a degraded DB
that still accepts connections will return 200 here; the readiness
probe (below) is where SQL reachability lives.

Kubernetes / Compose configuration: use this for `livenessProbe`. A
failing healthz means the pod should be restarted.

### `/readyz` — readiness

Implemented in
[`polaris-backend/src/api/readyz.rs`](../../polaris-backend/src/api/readyz.rs).
Returns a JSON body with five fields:

```json
{
  "ready": true,
  "signing_key_provisioned": true,
  "last_emit_at": "2026-05-15T19:00:00Z",
  "db_reachable": true,
  "setup_complete": true
}
```

- `ready` — true iff `signing_key_provisioned && db_reachable`. The
  orchestrator gates traffic on this field.
- `signing_key_provisioned` — true iff the active signer advertises
  a non-empty `did:key:z…`. The `StubSigner` returns "" until the
  wizard's step 1 mints a real key, so this is a precise
  distinguisher between "deferred provisioning" and "ready to emit."
- `last_emit_at` — RFC-3339 timestamp of the most recently emitted
  label, or `null` if no labels have ever been emitted. Operators
  alert on this field not advancing under load (suggests a wedged
  emitter).
- `db_reachable` — true iff `SELECT 1::int` returned successfully.
  False signals a complete pool / Postgres outage.
- `setup_complete` — true iff
  `polaris_setup_state.did_document_updated_at IS NOT NULL`. This
  field is **informational** — `ready` does not depend on it, so an
  operator can hit the setup wizard while traffic is being routed
  away.

Status code:

- `200 OK` when `ready == true`.
- `503 Service Unavailable` (same body) when `ready == false`.

Kubernetes / Compose configuration: use this for `readinessProbe`.
A failing readyz keeps the pod out of the load-balancer rotation
but does NOT restart it.

### When each fires false

| Condition                              | `/healthz` | `/readyz`     |
|----------------------------------------|------------|---------------|
| Process alive, DB pool healthy, key OK | 200        | 200           |
| Process alive, DB unreachable          | 503        | 503           |
| Process alive, DB OK, no signing key   | 200        | 503           |
| Setup wizard step 4 not yet run        | 200        | 200 (info)    |
| Process hung / unresponsive            | timeout    | timeout       |

---

## 6. Environment variable matrix

Every `POLARIS_*` variable the binary reads, with the source of
truth file reference and the default-when-unset behaviour.

| Variable                                      | Source                                                          | Default                  | Purpose                                                                 |
|-----------------------------------------------|-----------------------------------------------------------------|--------------------------|-------------------------------------------------------------------------|
| `DATABASE_URL`                                | `src/config.rs::DbConfig::from_env`                             | (required, no default)   | Postgres connection URL                                                 |
| `POLARIS_HTTP_BIND`                           | `src/config.rs::HttpConfig::from_env`                           | `127.0.0.1:8080`         | HTTP listener bind address                                              |
| `POLARIS_PROFILE`                             | `src/config.rs::Profile::from_env`                              | `labeler`                | `bluesky` (KMS-only) or `labeler` (file-plain allowed)                  |
| `POLARIS_COOKIE_KEY`                          | `src/config.rs::SecurityConfig::from_env`                       | (required in prod)       | 64-hex-char key for session-cookie encryption                           |
| `POLARIS_AUTH_BACKEND`                        | `src/config.rs::AuthConfig::from_env`                           | `oidc`                   | `oidc` or `atproto`                                                     |
| `POLARIS_REQUIRE_HARDWARE_KEY`                | `src/config.rs::AuthConfig::from_env`                           | `false`                  | Gate moderator login on WebAuthn / FIDO2                                |
| `POLARIS_OIDC_ISSUER_URL`                     | `src/config.rs::OidcConfig::from_env`                           | (empty)                  | OIDC issuer URL                                                         |
| `POLARIS_OIDC_CLIENT_ID`                      | `src/config.rs::OidcConfig::from_env`                           | (empty)                  | OIDC client id                                                          |
| `POLARIS_OIDC_CLIENT_SECRET`                  | `src/config.rs::OidcConfig::from_env`                           | (empty)                  | OIDC client secret (redacted in logs)                                   |
| `POLARIS_OIDC_REDIRECT_URL`                   | `src/config.rs::OidcConfig::from_env`                           | (empty)                  | OIDC redirect URL                                                       |
| `POLARIS_ATPROTO_CLIENT_METADATA`             | `src/config.rs::AtprotoConfig::from_env`                        | (empty)                  | Path to OAuth client_metadata.json                                      |
| `POLARIS_ATPROTO_CLIENT_ID`                   | `src/config.rs::AtprotoConfig::from_env`                        | (empty)                  | OAuth client_id URL                                                     |
| `POLARIS_LABELER_SIGNING_KEY_MODE`            | `src/config.rs::LabelerConfig::from_env`                        | `file-plain`             | `file-plain`, `passphrase-sealed`, `os-keychain`, `cloud-kms-oracle`    |
| `POLARIS_LABELER_SIGNING_KEY_PATH`            | `src/config.rs::LabelerConfig::from_env`                        | `/etc/polaris/labeler.key` | File-plain / passphrase-sealed key path                                |
| `POLARIS_LABELER_SIGNING_KEY_ACCOUNT`         | `src/config.rs::LabelerConfig::from_env`                        | `polaris/labeler`        | OS keychain account name                                                |
| `POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER`    | `src/config.rs::LabelerConfig::from_env`                        | `aws`                    | KMS provider                                                            |
| `POLARIS_LABELER_SIGNING_KEY_KMS_KEY_ID`      | `src/config.rs::LabelerConfig::from_env`                        | (empty)                  | KMS key ARN                                                             |
| `POLARIS_LABELER_SIGNING_KEY_KMS_REGION`      | `src/config.rs::LabelerConfig::from_env`                        | (empty)                  | KMS region                                                              |
| `POLARIS_PATTERN_ACTIONS_COSIGN_THRESHOLD`    | `src/config.rs::PatternActionsConfig::from_env`                 | `100`                    | Min subjects before pattern actions require senior co-sign              |
| `POLARIS_AGGREGATOR_BATCH_SIZE`               | `src/config.rs::AggregatorEnvConfig::from_env`                  | `50`                     | Report aggregator batch size                                            |
| `POLARIS_AGGREGATOR_POLL_INTERVAL_SECS`       | `src/config.rs::AggregatorEnvConfig::from_env`                  | `5`                      | Report aggregator poll interval (seconds)                               |
| `POLARIS_AGGREGATOR_WINDOW_SECS`              | `src/config.rs::AggregatorEnvConfig::from_env`                  | `3600`                   | Report aggregator dedup window (seconds)                                |
| `POLARIS_EVIDENCE_BLOB_STORE`                 | `src/config.rs::EvidenceConfig::from_env`                       | `in-memory`              | `in-memory`, `local-fs`, `s3`                                           |
| `POLARIS_EVIDENCE_LOCAL_FS_ROOT`              | `src/config.rs::EvidenceConfig::from_env`                       | `./evidence`             | Local-FS blob store root                                                |
| `POLARIS_EVIDENCE_WORKER_CONCURRENCY`         | `src/config.rs::EvidenceConfig::from_env`                       | `4`                      | Bounded concurrency for the evidence worker                             |
| `POLARIS_EVIDENCE_POLL_INTERVAL_SECS`         | `src/config.rs::EvidenceConfig::from_env`                       | `10`                     | Evidence worker poll interval                                           |
| `POLARIS_EVIDENCE_MAX_ATTEMPTS`               | `src/config.rs::EvidenceConfig::from_env`                       | `5`                      | Per-evidence retry cap                                                  |
| `POLARIS_EVIDENCE_RETRY_BASE_SECS`            | `src/config.rs::EvidenceConfig::from_env`                       | `60`                     | Exponential-backoff base                                                |
| `POLARIS_MODERATOR_ANOMALY_THRESHOLD`         | `src/config.rs::ModeratorAnomalyEnvConfig::from_env`            | `50`                     | T1 mitigation: actions-per-window threshold                             |
| `POLARIS_MODERATOR_ANOMALY_WINDOW_SECS`       | `src/config.rs::ModeratorAnomalyEnvConfig::from_env`            | `3600`                   | T1 mitigation: window size                                              |
| `POLARIS_FRONTEND_DIST`                       | `src/api/mod.rs::router_with_state`                             | (unset)                  | Directory holding the polaris-frontend SPA bundle                       |

KMS test fixtures (`POLARIS_KMS_TEST_*`) are read by the integration
tests behind the `kms-integration` Cargo feature, not by the
production binary.

---

## 7. Metrics surface — Prometheus series and alerting thresholds

The `/metrics` endpoint exposes Prometheus text-format output. The
recorder is installed once at process startup in `main.rs`; the
endpoint renders the global recorder's handle.

### Auto-instrumented series (from `axum-prometheus`)

| Series                                    | Type      | Labels                          | Alert idea                                          |
|-------------------------------------------|-----------|---------------------------------|-----------------------------------------------------|
| `axum_http_requests_total`                | counter   | `method`, `endpoint`, `status`  | `rate(...{status=~"5.."}[5m]) > 0.05 * rate(...[5m])` — 5xx error rate |
| `axum_http_requests_duration_seconds`     | histogram | `method`, `endpoint`, `status`  | `histogram_quantile(0.99, ...) > 1.0` — p99 latency > 1s |
| `axum_http_requests_pending`              | gauge     | `method`, `endpoint`            | `... > 100` — request backlog                       |

### Hand-emitted producer-slice counters

| Series                                      | Type    | Labels                                 | Site                                | Alert idea                                                                                |
|---------------------------------------------|---------|----------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------|
| `polaris_actions_total`                     | counter | `kind`                                 | `api::cases::submit_action`         | `rate(polaris_actions_total[5m]) == 0 for 1h` — labeler is idle (suspicious in business hours) |
| `polaris_labels_emitted_total`              | counter | `val`, `neg`                           | `LabelEmitter::emit`                | `increase(...[10m]) == 0` while `polaris_actions_total{kind="label"}` is increasing — emit is wedged |
| `polaris_subscribe_labels_subscribers`      | gauge   | (none)                                 | `labeler::server::run_subscription` | `... == 0 for 1h` — no AppView is consuming our labels                                    |
| `polaris_plc_operations_total`              | counter | `status` (`success` / `failed`)        | `api::setup::submit_plc_operation`  | `polaris_plc_operations_total{status="failed"} > 0` — alert on any PLC failure            |
| `polaris_setup_wizard_steps_total`          | counter | `step`, `status` (`success`/`failed`)  | `api::setup::*`                     | `rate(polaris_setup_wizard_steps_total{status="failed"}[15m]) > 0` — wizard wedged        |

`kind` values for `polaris_actions_total`: `label`, `takedown`,
`mute`, `warn`, `escalate`, `no_action`. The string form matches
`polaris_types::ActionKind::as_str` exactly.

`step` values for `polaris_setup_wizard_steps_total`:
`generate_key`, `publish_labeler_record`,
`request_plc_signature`, `submit_plc_operation`.

### Alerting recipe — labeler health dashboard

A reasonable starter dashboard at the Prometheus alert-rule level:

```yaml
groups:
- name: polaris-labeler
  rules:
  - alert: PolarisDown
    expr: up{job="polaris"} == 0
    for: 1m

  - alert: PolarisNotReady
    # /readyz returning 503 in last minute
    expr: |
      sum(rate(axum_http_requests_total{endpoint="/readyz",status="503"}[5m])) > 0
    for: 5m

  - alert: PolarisIdle
    # No actions in the last hour during business hours
    expr: rate(polaris_actions_total[5m]) == 0
    for: 1h

  - alert: PolarisPlcFailure
    expr: increase(polaris_plc_operations_total{status="failed"}[15m]) > 0

  - alert: PolarisEmitWedged
    expr: |
      increase(polaris_actions_total{kind=~"label|takedown"}[10m]) > 0
      and
      increase(polaris_labels_emitted_total[10m]) == 0

  - alert: PolarisNoLabelSubscribers
    expr: polaris_subscribe_labels_subscribers == 0
    for: 1h

  - alert: Polaris5xxRate
    expr: |
      sum(rate(axum_http_requests_total{status=~"5.."}[5m]))
      / sum(rate(axum_http_requests_total[5m])) > 0.05
    for: 10m

  - alert: PolarisP99Latency
    expr: histogram_quantile(0.99, rate(axum_http_requests_duration_seconds_bucket[5m])) > 1.0
    for: 10m
```

### Tracing — grep by action_id

Every action submitted through `POST /api/cases/{subject_id}/actions`
fires three tracing spans carrying the same `action_id` UUID (REQ-D3):

1. `submit_action` — at the HTTP handler entry
   (`src/api/cases.rs::submit_action`).
2. `emit_label` — at `LabelEmitter::emit`
   (`src/labeler/emitter.rs::emit`, via
   `#[tracing::instrument]`).
3. `broadcaster_publish` — at the broadcaster publish site inside
   `LabelEmitter::persist`.

An operator with a stuck action grep'es the structured-log output:

```
grep '<the-action-uuid>' /var/log/polaris/*.log
```

Three results means the action made it through all three stages.
Two results (missing `broadcaster_publish`) means the persist
succeeded but the broadcast failed — investigate the
`subscribe_labels` connection count. One result (only
`submit_action`) means the emitter rejected the action — check the
`EmitterError` log preceding the broken trace.

---

## 8. Common operator scenarios

### Scenario A — Restart a healthy labeler

`systemctl restart polaris-backend` is safe at any time. The
labeler's state lives in Postgres; the in-process active-signer is
re-loaded from the configured custody backend on every boot. A
restart while a moderator is mid-action returns a 503 to that single
in-flight request; the moderator retries.

### Scenario B — Postgres outage

`/healthz` returns 503. The orchestrator restarts the pod. After
the pod restarts but Postgres is still down, the binary still boots
(the `db::connect` retry loop is bounded) but `/readyz` returns 503
with `db_reachable: false`. The pod stays out of rotation until
Postgres recovers.

### Scenario C — Labeler signing key compromised

1. Rotate immediately using `labeler-key-rotate --mode <current>
   --new-key-path /tmp/labeler.key.new --reason "compromise"`.
2. Inspect `signing_key_history` to confirm the new row landed
   with `active_from = now()` and the prior row's `active_until`
   was set.
3. Verify the PLC operation step of the rotation succeeded — the
   moderator's DID document should advertise the new key.
4. Old signatures on existing labels remain verifiable against the
   historical key (rows in `signing_key_history`).

### Scenario D — Move from `file-plain` to `cloud-kms-oracle`

This is a hardening migration, not a rotation. Steps:

1. Provision the KMS key.
2. Stop the labeler.
3. Update env:
   `POLARIS_LABELER_SIGNING_KEY_MODE=cloud-kms-oracle` +
   `POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER=aws` +
   `POLARIS_LABELER_SIGNING_KEY_KMS_KEY_ID=arn:...` +
   `POLARIS_LABELER_SIGNING_KEY_KMS_REGION=us-east-1`.
4. Use `labeler-key-rotate --mode cloud-kms-oracle ...` to drive
   the rotation through the new custody backend. The on-disk
   `file-plain` key file should be securely deleted after the
   rotation completes.

### Scenario E — The wizard's PLC step rejected `invalidToken`

The PLC operation token from the email is single-use and
time-bounded. If step 3's email arrived and step 4 was not run
within the token's TTL, the token is expired. Recovery: re-run
step 3 (request a fresh token), then step 4. The DB column
`did_document_updated_at` is the gate — it stays NULL until step 4
succeeds, so re-running steps 3 + 4 is idempotent.

---

## 8b. Producer-slice smoke test (`cargo xtask smoke-local`)

`cargo xtask smoke-local` runs a hermetic end-to-end test that walks
the entire producer slice (login → setup wizard → action submission
→ firehose verify) against a mock fetcher and a testcontainer
Postgres. Same test the CI `test` job (REQ-E4) reruns on every PR.

```bash
SQLX_OFFLINE=true cargo xtask smoke-local
```

**Prerequisites:**

- Docker daemon reachable (the test prints a `SKIP` line and exits 0
  when Docker is unreachable, so a CI-less laptop is not blocked).
- The workspace's pinned Rust toolchain (`rust-toolchain.toml` →
  1.88 today).
- `SQLX_OFFLINE=true` because the workspace uses `sqlx` macros with
  a checked-in `.sqlx/` query cache; the offline mode skips the
  `DATABASE_URL` check at compile time.

**What the smoke covers:**

1. Boot the production router via
   `polaris_backend::api::router_with_state` on a dynamic port.
2. Drive ATProto OAuth login (start_login + complete_login) under
   a `MockFetcher` that canned-responds to every outbound HTTP call
   (PDS metadata, AS metadata, PAR, /oauth/token, plc.directory).
3. `GET /api/whoami` → assert `first_run == true`.
4. Walk all four `/api/setup/*` wizard steps. Assert the
   `signPlcOperation` request body's six shape facts (the same
   facts `tests/setup_plc_op_shape.rs` pins).
5. `GET /api/whoami` again → assert `first_run == false`.
6. Submit a Label action via `POST /api/cases/{subject_id}/actions`.
7. Open a `subscribeLabels` WebSocket, receive the live label
   frame, and verify the wire-extracted signature against the
   labeler's `signing_pubkey_did` via
   `polaris_backend::labeler::verify::verify_label`.
8. `GET /metrics` → assert `polaris_actions_total{kind="label"}`
   and `polaris_setup_wizard_steps_total{step="generate_key",
   status="success"}` both fired.

**Direct invocation (for debugging):**

```bash
SQLX_OFFLINE=true cargo test -p polaris-backend --test smoke_e2e -- --nocapture
```

Add `RUST_LOG=polaris_backend=trace` to surface every WARN emitted
by the setup handlers when a step fails.

**Test file:** `polaris-backend/tests/smoke_e2e.rs`.

---

## 9. Source of truth

This runbook is verifiable against the source tree:

- Setup wizard handlers:
  [`polaris-backend/src/api/setup.rs`](../../polaris-backend/src/api/setup.rs)
- Action precondition gate:
  [`polaris-backend/src/api/cases.rs`](../../polaris-backend/src/api/cases.rs)
- Signing key factory:
  [`polaris-backend/src/labeler/signer/mod.rs`](../../polaris-backend/src/labeler/signer/mod.rs)
- Stub signer (deferred provisioning):
  [`polaris-backend/src/labeler/signer/stub.rs`](../../polaris-backend/src/labeler/signer/stub.rs)
- Label emitter (active-signer watch channel):
  [`polaris-backend/src/labeler/emitter.rs`](../../polaris-backend/src/labeler/emitter.rs)
- Rotation state machine:
  [`polaris-backend/src/labeler/rotation.rs`](../../polaris-backend/src/labeler/rotation.rs)
- Rotation CLI:
  [`polaris-backend/src/bin/labeler_key_rotate.rs`](../../polaris-backend/src/bin/labeler_key_rotate.rs)
- Health probe:
  [`polaris-backend/src/api/healthz.rs`](../../polaris-backend/src/api/healthz.rs)
- Readiness probe:
  [`polaris-backend/src/api/readyz.rs`](../../polaris-backend/src/api/readyz.rs)
- Metrics endpoint:
  [`polaris-backend/src/api/metrics.rs`](../../polaris-backend/src/api/metrics.rs)
- Config loader:
  [`polaris-backend/src/config.rs`](../../polaris-backend/src/config.rs)
- Binary entrypoint:
  [`polaris-backend/src/main.rs`](../../polaris-backend/src/main.rs)

If anything in this runbook drifts from the source, the source
wins. File a PR.
