# Polaris quick-start (15-minute path)

Target: a labeler operator clones the repository, copies the env
template, sets a hostname + a signing-key path, runs
`docker compose up`, and has a working Polaris reachable on
`https://<their-domain>` within 15 minutes.

## Prerequisites (host)

- A Linux/macOS host with **Docker Engine ≥ 24** and **Docker Compose v2** (`docker compose`, not the legacy `docker-compose`).
- A **DNS A/AAAA record** pointing at the host (Caddy obtains a Let's Encrypt cert on first boot, which needs the host to be reachable on port 80 over the public internet).
- `openssl` for generating secrets.
- ~2 GB of free disk for the database + image cache.

## Steps

### 1. Clone the repository

```sh
git clone https://github.com/dollspace-gay/polaris
cd polaris/deploy
```

### 2. Copy the env template

```sh
cp .env.example .env
```

### 3. Edit `.env`

Open `deploy/.env` and set, at minimum:

- `POLARIS_HOSTNAME=<your-domain>` (the FQDN your DNS A record points at).
- `POSTGRES_PASSWORD=$(openssl rand -hex 24)`.
- `POLARIS_COOKIE_KEY=$(openssl rand -hex 32)` (must be 64 hex chars).
- `POLARIS_LABELER_SIGNING_KEY_PATH=/etc/polaris/keys/labeler.key` (the
  default, mounted in via the `polaris-keys` named volume).
- One of:
  - **OIDC backend** (default): `POLARIS_OIDC_ISSUER_URL`,
    `POLARIS_OIDC_CLIENT_ID`, `POLARIS_OIDC_CLIENT_SECRET`,
    `POLARIS_OIDC_REDIRECT_URL`.
  - **ATProto OAuth backend**: set `POLARIS_AUTH_BACKEND=atproto` and
    `POLARIS_ATPROTO_CLIENT_METADATA` / `POLARIS_ATPROTO_CLIENT_ID`.

### 4. Provision the signing key

Generate a K-256 secret key (32 bytes, hex-encoded) and copy it into
the `polaris-keys` volume. The simplest path for a fresh install:

```sh
mkdir -p /var/lib/polaris-keys-staging
openssl rand -hex 32 > /var/lib/polaris-keys-staging/labeler.key
chmod 0600 /var/lib/polaris-keys-staging/labeler.key

# After `docker compose up` runs once and creates the volume, copy in:
docker run --rm -v polaris_polaris-keys:/keys -v /var/lib/polaris-keys-staging:/staging:ro \
  alpine:3.20 sh -c 'cp /staging/labeler.key /keys/labeler.key && chown 1000:1000 /keys/labeler.key && chmod 0600 /keys/labeler.key'

rm -f /var/lib/polaris-keys-staging/labeler.key
```

For production-grade custody (passphrase-sealed / OS keychain / cloud
KMS) see `docs/ops/key-custody.md` (filed alongside issue #29).

### 5. Bring up the stack

```sh
docker compose up -d
```

The first run builds the `polaris-backend` image locally (~3-5 min on a
modern laptop), pulls postgres + redis + nats + caddy, then starts the
stack. Compose waits for the dependencies' healthchecks before starting
`polaris-backend`.

### 6. Verify

```sh
# Liveness via the internal port (only Caddy is published).
docker compose exec polaris-backend wget -qO- http://127.0.0.1:8080/healthz
# Expect: {"status":"ok","db":"ok"}

# Once DNS has propagated and Caddy has issued a cert:
curl -fsSL https://<your-domain>/healthz
```

### 7. Publish your labeler service record

Polaris ships a CLI that writes the `app.bsky.labeler.service` record
to your operator account so Bluesky clients discover your label
definitions. Dry-run first:

```sh
docker compose exec polaris-backend polaris-publish-labeler-record \
  --account did:plc:<your-operator-did> \
  --service-url https://<your-domain> \
  --signing-pubkey did:key:<your-labeler-signing-did> \
  --dry-run
```

If the dry-run output looks correct, re-run without `--dry-run`. The
record is idempotent — re-running with the same parameters is a no-op.

### 8. Browse to your instance

Open `https://<your-domain>/` in a browser. The Leptos moderation
dashboard loads; sign in via the configured auth backend.

## Troubleshooting

- **`docker compose up` fails on `polaris-backend` build**: confirm
  Rust 1.88 alpine image is reachable (`docker pull rust:1.88-alpine3.20`).
  Set `POLARIS_IMAGE_TAG` to a pre-built tag in `.env` to skip the
  local build entirely.
- **Caddy stuck on cert issuance**: confirm port 80 is reachable from
  the public internet, and DNS resolves to this host. `docker compose
  logs caddy` shows the ACME challenge progress.
- **`healthz` returns 503**: `docker compose logs postgres polaris-backend`
  almost certainly shows a DSN mismatch or a missing migration.

## Next steps

- `docs/ops/backup.md` — set up Postgres PITR + audit-log object-lock
  storage before declaring this instance production-ready.
- `docs/ops/key-custody.md` (when issue #29 ships) — migrate from
  file-plain to passphrase-sealed / OS keychain / cloud KMS.
- `deploy/helm/` — same stack on Kubernetes for multi-replica
  deployments.
