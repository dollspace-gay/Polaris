# Polaris on bare systemd (no Docker)

Install posture for a single VM running Polaris directly under
`systemd`, without a Docker / Compose stack. Choose this when:

- You already operate Postgres + Redis on the host and don't want a
  second copy under Docker.
- You need hardening directives from `systemd.exec(5)` that the
  Docker runtime doesn't expose cleanly.
- The host is a bare-metal box, a VM in a restricted environment,
  or a Raspberry-Pi-class device where Docker is overkill.

For the supported "easy install" path (Docker compose stack with the
published image), see [`docs/ops/quick-start.md`](../../docs/ops/quick-start.md).
For Kubernetes see [`deploy/helm/README.md`](../helm/README.md).

## What ships in this directory

- [`polaris.service`](polaris.service) — the systemd unit file.
  Hardened (NoNewPrivileges, ProtectSystem=strict, RestrictAddressFamilies,
  CapabilityBoundingSet empty, MemoryDenyWriteExecute, SystemCallFilter,
  …). Type=exec; runs as a dedicated `polaris` system user.

There is no shell installer for the systemd posture today —
`scripts/install.sh` targets the compose stack. The installation
steps below are deliberately explicit so the operator sees exactly
what changes.

## Prerequisites

- Linux with `systemd` ≥ 245 (the unit uses `ProtectHostname`,
  `ProtectClock`, `RestrictSUIDSGID`).
- Postgres ≥ 14 reachable from the host (local install or managed).
- Redis ≥ 7 reachable from the host.
- (Optional but recommended) NATS with JetStream — the event bus
  works without NATS in single-host single-process mode, but a real
  NATS unlocks the supervisor's durable subscriptions.
- A reverse proxy with TLS termination (Caddy, nginx, or your
  organisation's standard). The unit binds the backend on a high
  port (default 8080 via `POLARIS_HTTP_BIND`); your reverse proxy
  fronts 443 → 8080.
- DNS pointing at the host. The OAuth `client_id` document must be
  reachable from the public internet for Bluesky's AS to validate
  the install.

## Install

### 1. Create the system user and directories

```sh
useradd --system --home /var/lib/polaris --shell /usr/sbin/nologin polaris
mkdir -p /var/lib/polaris/evidence /etc/polaris/keys /etc/polaris/oauth
chown -R polaris:polaris /var/lib/polaris /etc/polaris/keys
chmod 0700 /etc/polaris/keys
```

The systemd unit's `ReadWritePaths=/var/lib/polaris` directive
matches this layout. If you move these paths, edit the unit
correspondingly.

### 2. Obtain the `polaris-backend` binary

Two options, in order of preference:

**Option A — extract from the published Docker image (no Rust toolchain
required):**

```sh
docker pull ghcr.io/dollspace-gay/polaris-backend:latest
container=$(docker create ghcr.io/dollspace-gay/polaris-backend:latest)
docker cp "$container":/usr/local/bin/polaris-backend ./polaris-backend
docker rm "$container"
install -m 0755 ./polaris-backend /opt/polaris/polaris-backend
```

Pin a `vX.Y.Z` tag instead of `:latest` for reproducible installs.
The same workflow also ships `polaris-setup` at
`/usr/local/bin/polaris-setup` inside the image — copy it out the
same way if you want to use it (see step 3).

**Option B — build from source:**

```sh
git clone https://github.com/dollspace-gay/polaris
cd polaris
cargo build --release --workspace
install -m 0755 target/release/polaris-backend /opt/polaris/polaris-backend
install -m 0755 target/release/polaris-setup /opt/polaris/polaris-setup
```

Requires Rust ≥ 1.85 (pinned in `rust-toolchain.toml`).

### 3. Generate the environment file with polaris-setup (recommended)

`polaris-setup` writes a `.env` file with freshly-rolled cookie key
and Postgres password and a matching `client-metadata.json`. Run it
once, then move the outputs into place:

```sh
polaris-setup --hostname polaris.example.com --dir /tmp/polaris-bootstrap --non-interactive

install -m 0640 -o root -g polaris \
  /tmp/polaris-bootstrap/.env /etc/polaris/polaris.env
install -m 0644 \
  /tmp/polaris-bootstrap/client-metadata.json \
  /etc/polaris/oauth/client-metadata.json

rm -rf /tmp/polaris-bootstrap
```

The systemd unit's `EnvironmentFile=/etc/polaris/polaris.env`
directive matches this destination. The cookie key + Postgres
password are now `root:polaris 0640` — readable by the `polaris`
user the unit runs as, and nobody else.

**Alternative** (no `polaris-setup`): copy
`deploy/.env.example` to `/etc/polaris/polaris.env` and edit by
hand, generating secrets manually with `openssl rand -hex 32` and
`openssl rand -hex 24`. The format is identical; `polaris-setup`
just removes the openssl + sed dance.

### 4. Point the env file at your Postgres / Redis

Edit `/etc/polaris/polaris.env` to set `DATABASE_URL` (and Redis
host, NATS URL if you're running one). The default `polaris-setup`
output assumes the compose-internal hostname `postgres`, which won't
resolve on a bare-VM install — replace it with your actual
hostnames or `127.0.0.1` if you're running Postgres locally.

### 5. Install the systemd unit

```sh
install -m 0644 deploy/systemd/polaris.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now polaris
```

Verify:

```sh
systemctl status polaris
journalctl -u polaris -n 50 --no-pager
curl -fsS http://127.0.0.1:8080/healthz
```

### 6. Configure your reverse proxy

The unit binds the backend on `POLARIS_HTTP_BIND` (default
`127.0.0.1:8080`; override in `/etc/polaris/polaris.env`). Front it
with whichever TLS terminator you already operate:

- **Caddy** — see [`../Caddyfile.example`](../Caddyfile.example) for
  the snippet that matches the labeler profile (TLS via Let's
  Encrypt, reverse proxy to backend, security headers).
- **nginx / Apache** — a standard `proxy_pass`-style reverse proxy
  configuration. Pass through `Host`, `X-Forwarded-Proto`, and
  `X-Forwarded-For` headers.

### 7. Open firewall ports

The host needs:

- **80/tcp** — inbound, for ACME HTTP-01 challenges (if your
  reverse proxy terminates Let's Encrypt).
- **443/tcp** — inbound, for HTTPS.
- **5432/tcp**, **6379/tcp**, **4222/tcp** — internal only (Postgres,
  Redis, NATS); do not expose to the public internet.

Adjust for your firewall (`ufw`, `firewalld`, the cloud provider's
security group) per your operational standard.

### 8. Walk the in-app setup wizard

Browse to `https://polaris.example.com/`, log in via your Bluesky
account, and walk the three-step wizard (signing key, labeler
service record, DID document). The flow is identical to the
compose-stack flow — see [`quick-start.md`](../../docs/ops/quick-start.md)
§3–5.

## Logging

The unit logs to journald with `SyslogIdentifier=polaris`:

```sh
journalctl -u polaris -f
journalctl -u polaris --since "1 hour ago" --no-pager
```

For remote log aggregation, drop a `/etc/systemd/system/polaris.service.d/override.conf`
in place to add a syslog forwarder or to swap `StandardOutput=` to
the appropriate sink for your stack (`syslog`, `kmsg`, `file:/var/log/polaris.log`).
Loki + promtail, Vector, and Fluent Bit all work well; configure
them to scrape the journal rather than re-templating the unit.

## Upgrades

The compose-stack upgrade guide
([`docs/ops/upgrade.md`](../../docs/ops/upgrade.md)) covers the
migration model, signing-key continuity, and the rollback caveat —
all of that applies to the systemd posture too, with one
substitution: instead of `docker compose pull && up -d`, you:

1. Stop the unit: `systemctl stop polaris`.
2. Replace `/opt/polaris/polaris-backend` with the new binary
   (extract from a newer image tag per step 2 above, or `cargo
   build` from a newer source checkout).
3. Start the unit: `systemctl start polaris`.

Migrations run automatically on the next boot. The signing key
under `/etc/polaris/keys/` persists across binary swaps because it
is a host-filesystem path — there is no volume to lose.

For zero-downtime upgrades, run two instances behind your reverse
proxy on different ports and cut over once the new instance reports
`/healthz` 200; this is straightforward because the backend is
stateless. Most operators do not need this — a 5-second restart
window during a low-traffic period is acceptable.

## Hardening notes

The shipped unit applies the full `systemd.exec(5)` hardening stack
relevant to a stateless networked service:

- `NoNewPrivileges=true`, `ProtectSystem=strict`,
  `ProtectHome=true`, `PrivateTmp=true`, `PrivateDevices=true`
- `ProtectKernelTunables/Modules/Logs=true`,
  `ProtectControlGroups/Hostname/Clock=true`
- `RestrictRealtime/SUIDSGID/Namespaces=true`,
  `LockPersonality=true`, `MemoryDenyWriteExecute=true`
- `SystemCallFilter=@system-service`,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
- Empty `CapabilityBoundingSet` / `AmbientCapabilities` (the backend
  binds a high port — it never needs `CAP_NET_BIND_SERVICE`).

If you need to relax any of these (e.g. lower `LimitNOFILE` on a
small VM, or open more syscalls for an exotic glibc), use a
drop-in at `/etc/systemd/system/polaris.service.d/override.conf`
rather than editing the shipped unit.
