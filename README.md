# Polaris

A gift-quality replacement for Ozone built around moderation-as-pattern-recognition with a calibrated human-in-the-loop, not a ticket queue. Polaris is an ATProto labeler and moderation tool for Bluesky and independent labeler operators — MIT-licensed, designed for both Bluesky's multi-region deployment and single-VM community labelers sharing one codebase.

## Quick start

```sh
# Build all workspace crates
cargo build --workspace

# Run the backend (development mode)
cargo run --package polaris-backend

# Run workspace tasks
cargo xtask --help
```

Requires Rust 1.85 or later (pinned in `rust-toolchain.toml`).

## Workspace layout

| Crate | Role |
|---|---|
| `polaris-types` | Plain Rust domain types shared by backend and frontend. No ATProto dependency. |
| `polaris-backend` | Axum HTTP server, labeler XRPC endpoint, ingest workers, label signing. |
| `polaris-frontend` | Leptos WASM moderation dashboard. |
| `xtask` | Workspace automation (`cargo xtask <subcommand>`). |

## Deployment

Operator artifacts live under [`deploy/`](deploy/) and the runbooks
under [`docs/ops/`](docs/ops/):

| Path | Purpose |
|---|---|
| `deploy/docker-compose.yaml` | Labeler-profile single-host stack (backend + Postgres + Redis + NATS + Caddy). |
| `deploy/Caddyfile.example` | TLS termination + reverse proxy template for the compose stack. |
| `deploy/.env.example` | Every env var `AppConfig` reads, documented inline. |
| `deploy/Dockerfile.labeler-profile` | Alpine-glibc-runtime image for self-hosted operators. |
| `deploy/Dockerfile.bluesky-profile` | `FROM scratch` musl-static image (≤ 50 MB budget) for first-party fleets. |
| `deploy/helm/` | Helm chart (Postgres + Redis + NATS sub-charts, Ingress, securityContext). |
| `deploy/systemd/polaris.service` | Bare-VM systemd unit with hardening directives. |
| `docs/ops/quick-start.md` | 15-minute clone-to-running runbook. |
| `docs/ops/backup.md` | Postgres PITR + S3-object-lock attestation + quarterly restore drill. |

The 15-minute path: `cp deploy/.env.example deploy/.env`, edit the
hostname + signing-key entries, run `docker compose -f deploy/docker-compose.yaml up -d`.

## License

MIT — see [`LICENSE`](LICENSE).
