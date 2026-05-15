# Polaris quick-start

Goal: from a fresh checkout to a running Polaris instance with your
labeler service record published and your DID document updated — all
through the browser, no CLI involvement past `docker compose up`.

## Prerequisites

- A Linux/macOS host with **Docker Engine ≥ 24** and **Docker Compose
  v2** (`docker compose`, not the legacy `docker-compose`).
- A **DNS A/AAAA record** pointing at the host. Caddy obtains a
  Let's Encrypt cert on first boot; that needs the host to be
  reachable on port 80 from the public internet.
- A **Bluesky account** (or any ATProto-compatible PDS account) you
  control — Polaris uses it both to log you in and to publish the
  labeler service record + DID document update.
- `openssl` (host-side, one-time, to generate cookie secrets).
- ~2 GB free disk for the database + image cache.

## 1. Clone the repo

```sh
git clone https://github.com/dollspace-gay/polaris
cd polaris/deploy
```

## 2. Copy and edit the env template

```sh
cp .env.example .env
```

Open `.env` and set:

- `POLARIS_HOSTNAME=<your-domain>` — the FQDN your DNS points at.
- `POSTGRES_PASSWORD=$(openssl rand -hex 24)`.
- `POLARIS_COOKIE_KEY=$(openssl rand -hex 32)` — must be 64 hex chars.
- `POLARIS_AUTH_BACKEND=atproto` — the in-browser login flow uses ATProto OAuth.
- `POLARIS_ATPROTO_CLIENT_ID=https://<your-domain>/oauth/client-metadata.json`
- `POLARIS_ATPROTO_CLIENT_METADATA=/etc/polaris/oauth/client-metadata.json`

Then create the OAuth client metadata file referenced above. The same file
gets served by Polaris at the `client_id` URL — Bluesky fetches it during
OAuth to verify your installation:

```sh
mkdir -p /etc/polaris/oauth
cat > /etc/polaris/oauth/client-metadata.json <<EOF
{
  "client_id": "https://<your-domain>/oauth/client-metadata.json",
  "application_type": "web",
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "atproto",
  "response_types": ["code"],
  "redirect_uris": ["https://<your-domain>/auth/atproto/callback"],
  "token_endpoint_auth_method": "none",
  "dpop_bound_access_tokens": true,
  "client_name": "Polaris (your installation)"
}
EOF
```

Mount that file into the container via `docker-compose.yaml` (the
default mount is `/etc/polaris/oauth:/etc/polaris/oauth:ro`).

## 3. Bring up the stack

```sh
docker compose up -d
```

First run builds the `polaris-backend` image (~3-5 min on a laptop),
pulls postgres + redis + nats + caddy, and starts everything. Compose
waits for the dependencies' healthchecks before starting
`polaris-backend`.

## 4. Open the URL and log in

Browse to `https://<your-domain>/`.

- You'll land on a login page asking for your Bluesky handle.
- Enter your handle (e.g., `mylabeler.bsky.social`) and click **Continue**.
- You're redirected to Bluesky to confirm the OAuth grant.
- After consent, you're redirected back to Polaris and your session
  cookie is set.

**You are now the first user of this Polaris install. Polaris
automatically grants you the `admin` role.** This is recorded in the
hash-chained audit log.

## 5. Walk the setup wizard

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

## 6. Verify external discovery

Open `https://bsky.app/profile/<your-handle>/labels` in a fresh
browser — you should see your declared label values listed. Within a
few minutes, Bluesky's AppViews will start subscribing to your
labeler endpoint and any labels you emit will appear at the right
subjects.

## CLI escape hatches

The browser wizard is the default operator path. The same operations
are also available as standalone CLIs, useful for scripted CI / IaC
pipelines and recovery scenarios:

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

- **`docker compose up` fails on `polaris-backend` build**: confirm
  the `rust:1.88-alpine3.20` base image is reachable. Set
  `POLARIS_IMAGE_TAG` in `.env` to a pre-built tag to skip the local
  build.
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

- `docs/ops/backup.md` — set up Postgres PITR + audit-log
  object-lock storage before declaring this instance production-ready.
- `docs/ops/key-custody.md` — migrate from file-plain custody to
  passphrase-sealed / OS keychain / cloud KMS for stronger at-rest
  protection. Driven by the `labeler-key-rotate` CLI.
- `deploy/helm/` — the same stack on Kubernetes, for multi-replica
  deployments.
