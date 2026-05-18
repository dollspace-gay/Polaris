# Polaris quick-start

Goal: from a fresh Linux host to a running Polaris instance with your
labeler service record published and your DID document updated — one
shell command for the bootstrap, then the rest is in the browser.

## Prerequisites

- A Linux/macOS host with **Docker Engine ≥ 24** and **Docker Compose
  v2** (`docker compose`, not the legacy `docker-compose`).
- A **DNS A/AAAA record** pointing at the host. Caddy obtains a
  Let's Encrypt cert on first boot; that needs the host to be
  reachable on port 80 from the public internet.
- A **Bluesky account** (or any ATProto-compatible PDS account) you
  control — Polaris uses it both to log you in and to publish the
  labeler service record + DID document update.
- ~2 GB free disk for the database + image cache.

(`openssl`, hand-templating client metadata, etc. are no longer
required — the install script generates everything for you.)

## 1. Install (one command)

From a checked-out repo:

```sh
git clone https://github.com/dollspace-gay/polaris
cd polaris
./scripts/install.sh
```

Or piped (no clone needed; the script clones into `./polaris` by
default):

```sh
POLARIS_HOSTNAME=mod.example.com bash -c \
  'curl -sSL https://raw.githubusercontent.com/dollspace-gay/polaris/main/scripts/install.sh | bash'
```

`POLARIS_HOSTNAME` is required when piped (no tty is attached to
prompt you). From a local repo with a tty, the script prompts
interactively.

What `install.sh` does, in order:

1. Verifies Docker and Docker Compose v2 are installed.
2. Clones the repo into `${POLARIS_INSTALL_DIR:-./polaris}` if you
   piped through `curl`.
3. Locates (or builds, via `cargo build --release --bin polaris-setup`)
   the `polaris-setup` binary.
4. Runs `polaris-setup --dir=deploy [--hostname=…] [--non-interactive]
   [--force]` which writes `deploy/.env` (chmod 0600) with freshly-
   rolled `POLARIS_COOKIE_KEY` (64 hex chars) and `POSTGRES_PASSWORD`
   (48 hex chars), plus `deploy/client-metadata.json` with your
   hostname substituted into the `client_id` URL.
5. Prints the exact `docker compose` command to bring up the stack.

The script does **not** auto-run `docker compose up`. Review
`deploy/.env` first, then continue with step 2.

Other environment knobs (run `./scripts/install.sh --help` for the
full list): `POLARIS_NONINTERACTIVE=1` forces non-interactive mode
even with a tty; `POLARIS_FORCE=1` passes `--force` to
`polaris-setup` (overwrites pre-existing `.env`); `POLARIS_INSTALL_DIR`
overrides the clone target (default `./polaris`); `POLARIS_VERSION`
selects a `polaris-setup` release tag (default `latest`). The script
also accepts `--dry-run` to print the commands it would run without
executing them.

## 2. Bring up the stack

```sh
docker compose -f deploy/docker-compose.yaml up -d
```

First run pulls `ghcr.io/dollspace-gay/polaris-backend:latest`
(multi-arch, amd64 + arm64), `postgres`, `redis`, `nats`, and `caddy`,
and starts everything. Compose waits for the dependencies'
healthchecks before starting `polaris-backend`. Pin
`POLARIS_IMAGE_TAG=vX.Y.Z` in `deploy/.env` for reproducible upgrades.

## 3. Open the URL and log in

Browse to `https://<your-hostname>/`.

- You'll land on a login page asking for your Bluesky handle.
- Enter your handle (e.g., `mylabeler.bsky.social`) and click **Continue**.
- You're redirected to Bluesky to confirm the OAuth grant.
- After consent, you're redirected back to Polaris and your session
  cookie is set.

**You are now the first user of this Polaris install. Polaris
automatically grants you the `admin` role.** This is recorded in the
hash-chained audit log.

## 4. Walk the setup wizard

On first run, Polaris detects there are no labels yet and routes `/`
to the **setup wizard** at `/setup`. Three steps:

1. **Generate signing key** — click the button. Polaris generates a
   K-256 keypair, writes the secret to the operator-configured path
   (mode 0o600), and displays the public `did:key:z…` for confirmation.
2. **Publish labeler service record** — the form is pre-populated with
   your domain and a starter label-value list (`spam`, `nsfw`,
   adjust as needed). Click **Publish**. Polaris uses your logged-in
   OAuth session to write the `app.bsky.labeler.service` record to
   your account.
3. **Update DID document** — click **Request PLC signature**.
   Bluesky's PDS sends a confirmation token to the email associated
   with your account. Paste that token into the form, click
   **Submit**. Polaris signs the PLC operation and submits it to the
   PLC directory. Your DID document now carries the
   `#atproto_labeler` service entry pointing at your Polaris
   installation.

After step 3 succeeds, you'll be redirected to the moderation dashboard.

## 5. Verify external discovery

Open `https://bsky.app/profile/<your-handle>/labels` in a fresh
browser — you should see your declared label values listed. Within a
few minutes, Bluesky's AppViews will start subscribing to your
labeler endpoint and any labels you emit will appear at the right
subjects.

## 6. Third-party labels — expect a multi-hour cold-start

The case-view's "Third-party labels" panel shows labels emitted by
*other* labelers on the AT-Proto network — i.e., what every other
labeler service has said about a given subject. Polaris discovers
those labelers by walking the public PLC directory's `/export`
log and subscribes to each one's `subscribeLabels` firehose; the
results land in the local `indexed_labels` table which the panel
reads.

**This bootstrap takes roughly 2–3 hours on a fresh deploy.** The
PLC log contains ~10M+ DID operations going back to November 2022;
labeler service records are a small fraction of those, and the
crawler walks chronologically with a polite 250ms inter-page delay.
During the bootstrap:

- The "Third-party labels" panel will show "No third-party labels are
  currently applied to this account" for every subject — even when
  the bsky AppView shows labels via its own indexing. This is
  expected. The panel populates organically as discovery finds
  labelers, the supervisor spawns subscribers, and labels stream in.
- Polaris's *own* labeling (the action composer, case workflow, your
  emitted labels via `subscribeLabels`) is unaffected — that path
  uses the local `labels` table, not `indexed_labels`.

See `docs/ops/runbook.md` §1a for the detailed time budget and
queries to monitor bootstrap progress. After the first full pass
completes, subsequent delta passes (every 6 hours) catch new
labelers in seconds.

## CLI escape hatches

The browser wizard + `install.sh` are the default operator path. The
same operations are also available as standalone CLIs, useful for
scripted CI / IaC pipelines and recovery scenarios:

- `polaris-setup` — the config-templating step `install.sh` runs.
  Flags: `--hostname <fqdn>`, `--non-interactive`, `--force`,
  `--dir <path>` (default `.`). Useful when you want to drop the
  generated `.env` and `client-metadata.json` into a config-management
  flow without going through the bash wrapper. Exit codes: `0`
  success, `1` user error (bad input, pre-existing file without
  `--force`), `2` internal error (RNG/IO failure).
- `polaris-publish-labeler-record` — write the labeler service
  record. Supports `--oauth` (browser-driven) and
  `--app-password-stdin` (CI-friendly) auth modes.
- `polaris-publish-did-service` — update the DID document. Same
  auth-mode flags.
- `labeler-key-rotate` — rotate the signing key with full state-
  machine resume support. Required for non-file-plain custody modes
  (passphrase-sealed, OS keychain, cloud KMS).

See each binary's `--help` for the full surface.

## Troubleshooting

- **`install.sh` says "docker is required but not installed"**:
  install Docker Engine ≥ 24 (and the Compose v2 plugin —
  `docker compose version` must succeed) and re-run.
- **`install.sh` errors with "Docker Compose v2 is required"**: you
  likely have the legacy `docker-compose` binary on PATH but not the
  v2 plugin. See <https://docs.docker.com/compose/install/>.
- **`polaris-setup: error: user: .env already exists`**: the install
  script is idempotent — re-running on a host that already has
  `deploy/.env` refuses to overwrite. Either delete the existing
  file or re-run with `POLARIS_FORCE=1 ./scripts/install.sh` to
  regenerate (destroys the previous cookie key and Postgres
  password).
- **`POLARIS_HOSTNAME` typo in `.env`**: edit `deploy/.env` directly
  and update both `POLARIS_HOSTNAME` and
  `POLARIS_ATPROTO_CLIENT_ID=https://<hostname>/oauth/client-metadata.json`,
  then restart with `docker compose -f deploy/docker-compose.yaml up -d`.
  Caddy will request a fresh cert for the corrected name.
- **`POLARIS_IMAGE_TAG` typo**: a missing or misspelled tag (e.g.
  `POLARIS_IMAGE_TAG=lastest`) makes `docker compose pull` fail with
  "manifest unknown". Set it to `latest` (or leave it unset/commented
  out — the compose default is `latest`).
- **`docker compose pull` fails to pull the published image**: the
  registry is `ghcr.io/dollspace-gay/polaris-backend`. If you're
  behind a corporate proxy without GHCR access, uncomment the
  `build:` block in `deploy/docker-compose.yaml` (and comment out
  the `image:` line) to build from source locally.
- **Caddy stuck on cert issuance**: confirm port 80 is reachable from
  the public internet and DNS resolves to this host.
  `docker compose logs caddy` shows the ACME challenge progress.
- **`/healthz` returns 503**: `docker compose logs postgres
  polaris-backend` will show a DSN mismatch or a missing migration.
- **OAuth login bounces to an error page**: Bluesky's AS must be
  able to GET your `client_id` URL. If your installation is behind
  a corporate firewall or non-public IP, that fetch will fail —
  the `client_id` document must be reachable from the public
  internet.
- **Setup wizard step 3 times out**: the PLC operation email is
  sometimes slow to arrive. Refresh the page and re-request the
  signature; the wizard remembers your earlier progress so you
  don't have to redo step 2.

## Next steps

- [`docs/ops/upgrade.md`](upgrade.md) — pin a tag, pull, and `up -d`
  without losing your signing key.
- [`docs/ops/backup.md`](backup.md) — set up Postgres PITR + audit-log
  object-lock storage before declaring this instance production-ready.
- `docs/ops/key-custody.md` — migrate from file-plain custody to
  passphrase-sealed / OS keychain / cloud KMS for stronger at-rest
  protection. Driven by the `labeler-key-rotate` CLI.
- [`deploy/helm/`](../../deploy/helm/) — the same stack on Kubernetes,
  for multi-replica deployments.
- [`deploy/systemd/`](../../deploy/systemd/) — bare-VM install posture
  (no Docker).
