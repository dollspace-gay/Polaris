# Polaris

A gift-quality replacement for Ozone built around moderation-as-pattern-recognition with a calibrated human-in-the-loop, not a ticket queue. Polaris is an ATProto labeler and moderation tool for Bluesky and independent labeler operators — MIT-licensed, designed for both Bluesky's multi-region deployment and single-VM community labelers sharing one codebase.

## Quick start

There are two paths through Polaris depending on what you're trying to
do. Operators ship it; developers extend it.

### Path A — Operator (deploy Polaris)

One command from a fresh Linux host:

```sh
curl -sSL https://raw.githubusercontent.com/dollspace-gay/polaris/main/scripts/install.sh | bash
```

Or, from a checked-out repo:

```sh
./scripts/install.sh
```

The script verifies Docker + Compose v2, locates (or builds) the
`polaris-setup` binary, generates `deploy/.env` (mode 0600) and
`client-metadata.json` with freshly-rolled secrets, and prints the
exact `docker compose up -d` command for you to run. It never
auto-starts the stack.

Set `POLARIS_HOSTNAME` in the environment before piping when there's
no tty (i.e. the `curl … | bash` path):

```sh
POLARIS_HOSTNAME=mod.example.com bash -c \
  'curl -sSL https://raw.githubusercontent.com/dollspace-gay/polaris/main/scripts/install.sh | bash'
```

The full 15-minute walkthrough — including the in-browser setup wizard
(signing key, labeler service record, DID document) and the
multi-hour third-party-labels cold-start — is in
[`docs/ops/quick-start.md`](docs/ops/quick-start.md). Upgrading an
existing install is covered in [`docs/ops/upgrade.md`](docs/ops/upgrade.md).

### Path B — Developer (work on Polaris)

```sh
# Build all workspace crates
cargo build --workspace

# Run the backend (development mode)
cargo run --package polaris-backend

# Run workspace tasks
cargo xtask --help
```

Requires Rust 1.85 or later (pinned in `rust-toolchain.toml`).

Operators do not need to build from source — the `ghcr.io/dollspace-gay/polaris-backend`
image (multi-arch: linux/amd64 + linux/arm64) is the supported
production artefact, and `scripts/install.sh` is the supported entry
point.

## Workspace layout

| Crate | Role |
|---|---|
| `polaris-types` | Plain Rust domain types shared by backend and frontend. No ATProto dependency. |
| `polaris-backend` | Axum HTTP server, labeler XRPC endpoint, ingest workers, label signing. |
| `polaris-frontend` | Leptos WASM moderation dashboard. |
| `xtask` | Workspace automation (`cargo xtask <subcommand>`). |

## Deployment

Operator artefacts live under [`deploy/`](deploy/) and the runbooks
under [`docs/ops/`](docs/ops/):

| Path | Purpose |
|---|---|
| `scripts/install.sh` | One-shot operator bootstrapper. Checks prerequisites, runs `polaris-setup`, prints the `docker compose` command. |
| `polaris-backend/src/bin/polaris_setup.rs` | `polaris-setup` config-templating CLI: writes `.env` (mode 0600) + `client-metadata.json` with freshly-rolled secrets. Built as `cargo build -p polaris-backend --bin polaris-setup`; usable as an IaC escape hatch when you don't want the install script. |
| `ghcr.io/dollspace-gay/polaris-backend:latest` | Multi-arch (amd64 + arm64) published image. Compose pulls this by default; pin `POLARIS_IMAGE_TAG=vX.Y.Z` for reproducible upgrades. |
| `deploy/docker-compose.yaml` | Labeler-profile single-host stack (backend + Postgres + Redis + NATS + Caddy). |
| `deploy/Caddyfile.example` | TLS termination + reverse proxy template for the compose stack. |
| `deploy/.env.example` | Every env var `AppConfig` reads, documented inline. |
| `deploy/Dockerfile.labeler-profile` | Alpine-glibc-runtime image for self-hosted operators (source of the published image). |
| `deploy/Dockerfile.bluesky-profile` | `FROM scratch` musl-static image (≤ 50 MB budget) for first-party fleets. |
| `deploy/helm/` | Helm chart (Postgres + Redis + NATS sub-charts, Ingress, securityContext). See [`deploy/helm/README.md`](deploy/helm/README.md). |
| `deploy/systemd/polaris.service` | Bare-VM systemd unit with hardening directives. See [`deploy/systemd/README.md`](deploy/systemd/README.md). |
| `docs/ops/quick-start.md` | 15-minute install-to-running runbook for the compose stack. |
| `docs/ops/upgrade.md` | Standard upgrade flow, migration handling, and rollback. |
| `docs/ops/backup.md` | Postgres PITR + S3-object-lock attestation + quarterly restore drill. |

## License

MIT — see [`LICENSE`](LICENSE).
